package loop

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/contract"
)

// DefaultSkewMargin is the margin used when a task has no
// skew_margin_seconds (ADR 0001 section 2.5).
const DefaultSkewMargin = 5 * time.Second

// ceilSecond rounds t up to the next whole second. Kubernetes and ESO
// timestamps have second precision, so "strictly after T plus skew" is
// judged against the rounded-up bound and equal timestamps never count
// (ADR 0001 section 2.2).
func ceilSecond(t time.Time) time.Time {
	r := t.Truncate(time.Second)
	if r.Before(t) {
		r = r.Add(time.Second)
	}
	return r
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// passMarker is the change marker of one pass, built once from the task
// and filled with what the eso_sync stage of the pass saw.
type passMarker struct {
	change     connectors.Change
	writeBound time.Time // ceil(executed_at + skew)
}

func newPassMarker(t *contract.ObservationTask, cpOffset time.Duration) passMarker {
	margin := DefaultSkewMargin
	if t.SkewMarginSeconds != nil {
		margin = time.Duration(*t.SkewMarginSeconds) * time.Second
	}
	skew := margin + absDuration(cpOffset)
	ec := t.ExpectedChange
	ch := connectors.Change{
		RemoteKey:  ec.SecretRef.Name,
		ExecutedAt: ec.ExecutedAt,
		DeadlineAt: t.DeadlineAt,
		Skew:       skew,
		Baseline:   t.RolloutBaseline,
	}
	// A pinned-version link needs a version the agent reported; without
	// one the connectors are not given anything to match.
	if ec.VersionSource == "agent_reported" && ec.ProviderVersionID != nil {
		ch.ProviderVersionID = *ec.ProviderVersionID
	}
	for _, r := range t.ConnectorRefs {
		if r.Stage == contract.StageESOSync {
			ch.ESOExpected = true
		}
	}
	return passMarker{change: ch, writeBound: ceilSecond(ec.ExecutedAt.Add(skew))}
}

// noteESO records what the eso_sync stage of this pass saw, for the
// rollout stage that runs after it. Only an observed stage counts.
func (m *passMarker) noteESO(s contract.StageObservation) {
	f, ok := s.Facts.(*contract.ESOFacts)
	if !ok || f == nil {
		return
	}
	m.change.ESOTargetName = f.TargetSecretName
	if s.Outcome == contract.OutcomeObserved && f.RefreshTime != nil {
		m.change.ESORefreshTime = *f.RefreshTime
	}
}

// target builds the connectors.Target for one ref.
//
// NotBefore for workload_rollout follows ADR 0001 section 2.2 step 3:
// when the task expects eso_sync, a rollout must follow the ESO refresh
// that fetched the change, not only the write. The ESO refresh_time of
// this pass is a refresh after the change; so is
// rollout_baseline.observed_at, which the control plane copies from the
// earliest pass with eso_sync observed. The earlier of the two is used,
// because a refresh moves forward on every refreshInterval and the
// newest one would hide a rollout that followed an earlier qualifying
// refresh. Both are after the write, so the bound never drops below
// executed_at plus skew.
func (m *passMarker) target(ref contract.ConnectorRef) connectors.Target {
	tg := connectors.Target{ID: ref.TargetID, Stage: ref.Stage, NotBefore: m.writeBound}
	if ref.Stage != contract.StageWorkloadRollout {
		tg.Change = m.change
		tg.Change.ESORefreshTime, tg.Change.ESOTargetName = time.Time{}, ""
		return tg
	}
	tg.Change = m.change
	if !m.change.ESOExpected || m.change.ESORefreshTime.IsZero() {
		return tg
	}
	anchor := m.change.ESORefreshTime
	if b := m.change.Baseline; b != nil && b.ObservedAt.Before(anchor) && b.ObservedAt.After(m.change.ExecutedAt) {
		anchor = b.ObservedAt
	}
	if nb := ceilSecond(anchor.Add(m.change.Skew)); nb.After(tg.NotBefore) {
		tg.NotBefore = nb
	}
	return tg
}

// toStage turns a connector observation into a contract stage. Anything
// the contract cannot carry honestly becomes an error stage with a
// closed error code; connector error text is never copied. Linkage is
// derived here from the facts and the task, never taken from the
// connector.
func (l *Loop) toStage(ref contract.ConnectorRef, tg connectors.Target, obs connectors.Observation, err error, timedOut bool, log *slog.Logger) contract.StageObservation {
	observedAt := obs.ObservedAt.UTC()
	if obs.ObservedAt.IsZero() {
		observedAt = l.cfg.Now().UTC()
	}
	base := contract.StageObservation{
		Stage:      ref.Stage,
		Source:     contract.Source{ConnectorID: ref.ConnectorID, TargetID: ref.TargetID, API: contract.APIFor(ref.Stage)},
		ObservedAt: observedAt,
		Caveats:    []contract.Caveat{},
		Linkage:    contract.LinkageNone,
	}
	if ref.Stage == contract.StageArgoCDContext {
		// Every ArgoCD stage, errors included, says health is not proof.
		base.Caveats = []contract.Caveat{contract.CaveatArgoCDHealthNotProof}
	}
	errorStage := func(code contract.ErrorCode) contract.StageObservation {
		s := base
		s.Outcome, s.Confidence, s.ErrorCode = contract.OutcomeError, contract.ConfidenceNone, code
		return s
	}
	ev := obs.Evidence
	stageLog := log.With("connector_id", ref.ConnectorID, "target_id", ref.TargetID, "stage", string(ref.Stage))

	if err != nil || obs.Outcome == contract.OutcomeError {
		code := contract.ErrorInternal
		switch {
		case ev.ErrorCode.Valid() && ev.ErrorCode != contract.ErrorInternal:
			code = ev.ErrorCode
		case timedOut || errors.Is(err, context.DeadlineExceeded):
			code = contract.ErrorConnectorTimeout
		}
		s := errorStage(code)
		stageLog.Info("stage observed", "outcome", string(s.Outcome), "error_code", string(s.ErrorCode))
		return s
	}
	if ev.Resource == nil || ev.Facts == nil {
		stageLog.Warn("connector returned no evidence detail; reporting an internal error")
		return errorStage(contract.ErrorInternal)
	}

	s := base
	s.Outcome, s.Resource, s.Facts, s.Confidence = obs.Outcome, ev.Resource, ev.Facts, ev.Confidence
	if ev.Caveats != nil {
		s.Caveats = slices.Clone(ev.Caveats)
	}
	if s.Confidence == "" {
		s.Confidence = contract.ConfidenceNone
	}
	if ref.Stage == contract.StageArgoCDContext && !slices.Contains(s.Caveats, contract.CaveatArgoCDHealthNotProof) {
		s.Caveats = append(s.Caveats, contract.CaveatArgoCDHealthNotProof)
	}
	// Validate the connector's evidence before judging it, with a
	// linkage the stage accepts; the real linkage is set below.
	if s.Outcome == contract.OutcomeObserved && ref.Stage != contract.StageArgoCDContext {
		s.Linkage = contract.LinkageTimeOrdered
	}
	if verr := s.Validate(); verr != nil {
		// verr names a field and a rule, never a value.
		stageLog.Warn("connector evidence breaks the contract; reporting an internal error", "error", verr)
		return errorStage(contract.ErrorInternal)
	}
	var apiOffset time.Duration
	if obs.APIServerOffsetKnown {
		apiOffset = absDuration(obs.APIServerOffset)
	}
	if reason := holdsChain(&s, tg, apiOffset); reason != "" {
		stageLog.Info("observed outcome not supported by the facts; reporting not_observed", "rule", reason)
	}
	s.Linkage = deriveLinkage(s, tg)
	if s.Linkage == contract.LinkageTimeOrdered && ref.Stage == contract.StageESOSync {
		addCaveat(&s, contract.CaveatTemporalInferenceOnly)
	}
	if verr := s.Validate(); verr != nil {
		stageLog.Warn("stage breaks the contract after linkage; reporting an internal error", "error", verr)
		return errorStage(contract.ErrorInternal)
	}
	stageLog.Info("stage observed", "outcome", string(s.Outcome), "linkage", string(s.Linkage))
	return s
}

func addCaveat(s *contract.StageObservation, c contract.Caveat) {
	if !slices.Contains(s.Caveats, c) && len(s.Caveats) < contract.MaxCaveats {
		s.Caveats = append(s.Caveats, c)
	}
}

// deriveLinkage is the only place a linkage is chosen (ADR 0001 sections
// 2.2 and 2.3). Only an observed stage carries a link:
//   - eso_sync: version_pinned when the ExternalSecret pins the remote
//     version and that pin matches a provider version the agent
//     reported; otherwise time_ordered.
//   - workload_rollout: time_ordered.
//   - argocd_context: none, always.
func deriveLinkage(s contract.StageObservation, tg connectors.Target) contract.Linkage {
	if s.Outcome != contract.OutcomeObserved {
		return contract.LinkageNone
	}
	switch s.Stage {
	case contract.StageESOSync:
		f, _ := s.Facts.(*contract.ESOFacts)
		if f != nil && f.RemoteVersionPin == "matches_expected" && tg.Change.ProviderVersionID != "" {
			return contract.LinkageVersionPinned
		}
		return contract.LinkageTimeOrdered
	case contract.StageWorkloadRollout:
		return contract.LinkageTimeOrdered
	}
	return contract.LinkageNone
}

// holdsChain checks an observed eso_sync or workload_rollout stage
// against the rules of ADR 0001 sections 2.2 and 2.3 that the facts can
// show. When the facts do not support observed, the stage becomes
// not_observed (non-terminal, so the control plane looks again) with a
// caveat, and the rule that failed is returned. The control plane
// recomputes every outcome; this keeps the Gateway from attesting more
// than its own facts say.
func holdsChain(s *contract.StageObservation, tg connectors.Target, apiOffset time.Duration) string {
	if s.Outcome != contract.OutcomeObserved {
		return ""
	}
	bound := ceilSecond(tg.NotBefore.Add(apiOffset))
	downgrade := func(c contract.Caveat, rule string) string {
		s.Outcome = contract.OutcomeNotObserved
		if c != "" {
			addCaveat(s, c)
		}
		return rule
	}
	switch s.Stage {
	case contract.StageESOSync:
		f := s.Facts.(*contract.ESOFacts)
		switch {
		case f.ReadyStatus != "True":
			return downgrade("", "eso_not_ready")
		case f.RemoteRefMatch == "mismatch":
			return downgrade(contract.CaveatRemoteRefMismatch, "eso_remote_ref_not_matched")
		case f.RemoteRefMatch == "extract_or_find":
			return downgrade(contract.CaveatDataFromExtractOrFind, "eso_remote_ref_not_matched")
		case f.RemoteRefMatch != "match":
			return downgrade(contract.CaveatRemoteRefNotChecked, "eso_remote_ref_not_matched")
		case f.RemoteVersionPin == "other_version":
			return downgrade(contract.CaveatRemoteVersionPinnedOther, "eso_pinned_other_version")
		case f.RefreshTime == nil || !f.RefreshTime.After(bound):
			c := contract.CaveatRefreshBeforeChange
			if f.RefreshTime != nil && f.RefreshTime.After(tg.Change.ExecutedAt) {
				c = contract.CaveatRefreshTimeWithinSkew
			}
			return downgrade(c, "eso_refresh_not_after_change")
		}
	case contract.StageWorkloadRollout:
		f := s.Facts.(*contract.RolloutFacts)
		switch {
		case tg.Change.ESOExpected && tg.Change.ESORefreshTime.IsZero():
			return downgrade(contract.CaveatRolloutNotTriggeredByChange, "rollout_without_eso_refresh")
		case f.SpecReplicas == 0 || (f.Paused != nil && *f.Paused):
			return downgrade(contract.CaveatRolloutInProgress, "rollout_cannot_complete")
		case !rolloutComplete(f):
			return downgrade(contract.CaveatRolloutInProgress, "rollout_not_complete")
		case !rolloutTriggered(f, tg, bound):
			return downgrade(contract.CaveatRolloutNotTriggeredByChange, "rollout_not_after_change")
		}
	}
	return ""
}

// rolloutComplete is the kubectl rollout status rule (ADR 0001 section
// 2.2 step 3).
func rolloutComplete(f *contract.RolloutFacts) bool {
	if f.UpdatedReplicas == nil || f.Replicas == nil || f.AvailableReplicas == nil {
		return false
	}
	return f.ObservedGeneration >= f.Generation && *f.UpdatedReplicas == f.SpecReplicas &&
		*f.Replicas == *f.UpdatedReplicas && *f.AvailableReplicas == *f.UpdatedReplicas
}

// rolloutTriggered is the qualifying-rollout rule (runtime design 3.4).
func rolloutTriggered(f *contract.RolloutFacts, tg connectors.Target, bound time.Time) bool {
	switch f.RolloutTrigger {
	case "replicaset_created_after_change":
		return f.NewestReplicaSetCreatedAt != nil && f.NewestReplicaSetCreatedAt.After(bound)
	case "replicaset_revision_bumped_after_change":
		b := tg.Change.Baseline
		if b == nil {
			return false
		}
		cur, err1 := strconv.ParseInt(f.DeploymentRevision, 10, 64)
		base, err2 := strconv.ParseInt(b.DeploymentRevision, 10, 64)
		return err1 == nil && err2 == nil && cur > base
	}
	return false
}
