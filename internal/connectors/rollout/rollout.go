// Package rollout is the read-only connector for workload rollout
// status: one apps/v1 Deployment and the ReplicaSets it owns.
//
// Each Observe call is one snapshot: a GET of the Deployment and a
// bounded, label-selected LIST of ReplicaSets in its namespace. It reads
// no pods, no logs, no events and never a Secret. The link to the
// change is time order only (a ReplicaSet created after the change
// marker), so the connector reports observed at most, never verified.
package rollout

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/kube"
	"github.com/secrets-bridge/gateway/internal/safetext"
)

// ReplicaSet list paging: pages of listPageSize, at most listMaxPages.
const (
	listPageSize = 50
	listMaxPages = 4
)

// Reason codes this connector sets on an Observation.
const (
	ReasonTargetNotConfigured      = "target_not_configured"
	ReasonNamespaceNotAllowed      = "namespace_not_allowed"
	ReasonChangeMarkerMissing      = "change_marker_missing"
	ReasonRolloutPaused            = "rollout_paused"
	ReasonScaledToZero             = "scaled_to_zero"
	ReasonSelectorUnsupported      = "selector_unsupported"
	ReasonReplicaSetListTruncated  = "replicaset_list_truncated"
	ReasonGenerationNotObserved    = "generation_not_observed"
	ReasonNewReplicaSetAvailable   = "new_replicaset_available"
	ReasonRolloutInProgress        = "rollout_in_progress"
	ReasonProgressDeadlineExceeded = "progress_deadline_exceeded"
	ReasonNoRolloutSinceChange     = "no_rollout_since_change"
	ReasonNoReloadMechanism        = "no_reload_mechanism"
)

type apiClient interface {
	Get(ctx context.Context, apiPath string, query url.Values, out any) error
}

// Connector observes Deployment rollouts in its allowed namespaces.
type Connector struct {
	name       string
	namespaces map[string]struct{}
	targets    map[string]Target
	api        apiClient
	now        func() time.Time
}

func newConnector(name string, s Settings, api apiClient, now func() time.Time) *Connector {
	if now == nil {
		now = time.Now
	}
	c := &Connector{
		name:       name,
		namespaces: make(map[string]struct{}, len(s.Namespaces)),
		targets:    make(map[string]Target, len(s.Targets)),
		api:        api,
		now:        now,
	}
	for _, ns := range s.Namespaces {
		c.namespaces[ns] = struct{}{}
	}
	for _, t := range s.Targets {
		c.targets[t.ID] = t
	}
	return c
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Kind implements connectors.Connector.
func (c *Connector) Kind() connectors.Kind { return connectors.KindRollout }

// Observe implements connectors.Connector.
func (c *Connector) Observe(ctx context.Context, target connectors.Target) (connectors.Observation, error) {
	obs := connectors.Observation{
		Connector: c.name,
		Kind:      connectors.KindRollout,
		TargetID:  target.ID,
		Stage:     connectors.StageWorkloadRollout,
	}
	done := func(o connectors.Outcome, reason string) (connectors.Observation, error) {
		obs.Outcome = o
		obs.Reason = reason
		obs.ObservedAt = c.now().UTC()
		return obs, nil
	}

	t, ok := c.targets[target.ID]
	if !ok {
		return done(connectors.OutcomeError, ReasonTargetNotConfigured)
	}
	if _, ok := c.namespaces[t.Namespace]; !ok {
		// Checked before any request: a target outside the allowed
		// namespaces is never read, whatever RBAC would permit.
		return done(connectors.OutcomeUnverifiable, ReasonNamespaceNotAllowed)
	}

	depPath, err := kube.ResourcePath("apps", "v1", t.Namespace, "deployments", t.Deployment)
	if err != nil {
		return done(connectors.OutcomeError, "internal")
	}
	var dep deployment
	if err := c.api.Get(ctx, depPath, nil, &dep); err != nil {
		return done(connectors.OutcomeError, kube.ErrorCode(err))
	}

	selector, ok := dep.Spec.Selector.String()
	if !ok || dep.Metadata.UID == "" {
		obs.Rollout = deploymentFacts(dep)
		return done(connectors.OutcomeUnverifiable, ReasonSelectorUnsupported)
	}
	rss, truncated, err := c.listReplicaSets(ctx, t.Namespace, selector)
	if err != nil {
		obs.Rollout = deploymentFacts(dep)
		if errors.Is(err, kube.ErrInvalidConfig) {
			return done(connectors.OutcomeError, "internal")
		}
		return done(connectors.OutcomeError, kube.ErrorCode(err))
	}

	facts, current := buildFacts(dep, rss)
	anchor := ceilSecond(target.NotBefore)
	facts.RolloutTrigger = trigger(target.NotBefore, anchor, facts, current)
	obs.Rollout = facts

	if truncated {
		return done(connectors.OutcomeUnverifiable, ReasonReplicaSetListTruncated)
	}
	if target.NotBefore.IsZero() {
		return done(connectors.OutcomeUnverifiable, ReasonChangeMarkerMissing)
	}
	if facts.Paused {
		return done(connectors.OutcomeUnverifiable, ReasonRolloutPaused)
	}
	if facts.SpecReplicas == 0 {
		return done(connectors.OutcomeUnverifiable, ReasonScaledToZero)
	}
	if facts.ObservedGeneration < facts.Generation {
		obs.Caveats = obs.Caveats.With(connectors.CaveatGenerationNotObserved)
		return done(connectors.OutcomeNotObserved, ReasonGenerationNotObserved)
	}

	if facts.RolloutTrigger == connectors.TriggerReplicaSetAfterChange {
		obs.Caveats = obs.Caveats.With(connectors.CaveatTemporalInferenceOnly)
		switch {
		case complete(facts, current):
			return done(connectors.OutcomeObserved, ReasonNewReplicaSetAvailable)
		case facts.ProgressingReason == "ProgressDeadlineExceeded":
			return done(connectors.OutcomeNotObserved, ReasonProgressDeadlineExceeded)
		default:
			obs.Caveats = obs.Caveats.With(connectors.CaveatRolloutInProgress)
			return done(connectors.OutcomeNotObserved, ReasonRolloutInProgress)
		}
	}

	// No ReplicaSet newer than the change.
	if facts.ReloadMechanism == connectors.ReloadNoneDetected {
		// Nothing configured to restart the pods: an env consumer will
		// not pick up the change until something restarts it, and a
		// volume consumer refreshes without any rollout to observe.
		// Waiting longer would not change the answer.
		obs.Caveats = obs.Caveats.With(connectors.CaveatReloadMechanismUnknown)
		return done(connectors.OutcomeUnverifiable, ReasonNoReloadMechanism)
	}
	obs.Caveats = obs.Caveats.With(connectors.CaveatRolloutNotTriggeredByChange)
	if facts.RolloutTrigger == connectors.TriggerAnnotationAfterChange {
		// restartedAt is after the change but no matching ReplicaSet is:
		// the clocks disagree or the controller has not caught up.
		obs.Caveats = obs.Caveats.With(connectors.CaveatClockSkewSuspected)
	}
	return done(connectors.OutcomeNotObserved, ReasonNoRolloutSinceChange)
}

func (c *Connector) listReplicaSets(ctx context.Context, ns, selector string) ([]replicaSet, bool, error) {
	p, err := kube.ResourcePath("apps", "v1", ns, "replicasets", "")
	if err != nil {
		return nil, false, err
	}
	var out []replicaSet
	cont := ""
	for range listMaxPages {
		q := url.Values{"labelSelector": {selector}, "limit": {strconv.Itoa(listPageSize)}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page replicaSetList
		if err := c.api.Get(ctx, p, q, &page); err != nil {
			return nil, false, err
		}
		out = append(out, page.Items...)
		cont = page.Metadata.Continue
		if cont == "" {
			return out, false, nil
		}
	}
	return out, true, nil
}

func deploymentFacts(d deployment) connectors.RolloutFacts {
	spec := int64(1)
	if d.Spec.Replicas != nil {
		spec = *d.Spec.Replicas
	}
	f := connectors.RolloutFacts{
		Present:             true,
		Generation:          nonNeg(d.Metadata.Generation),
		ObservedGeneration:  nonNeg(d.Status.ObservedGeneration),
		SpecReplicas:        nonNeg(spec),
		Replicas:            nonNeg(d.Status.Replicas),
		UpdatedReplicas:     nonNeg(d.Status.UpdatedReplicas),
		ReadyReplicas:       nonNeg(d.Status.ReadyReplicas),
		AvailableReplicas:   nonNeg(d.Status.AvailableReplicas),
		UnavailableReplicas: nonNeg(d.Status.UnavailableReplicas),
		Paused:              d.Spec.Paused,
		DeploymentRevision:  safetext.Revision(d.Metadata.Annotations.revision),
		RolloutTrigger:      connectors.TriggerNotChecked,
		ReloadMechanism:     reloadMechanism(d),
	}
	for _, cond := range d.Status.Conditions {
		switch cond.Type {
		case "Progressing":
			f.ProgressingStatus = safetext.ConditionStatus(cond.Status)
			f.ProgressingReason = safetext.ConditionReason(cond.Reason)
		case "Available":
			f.AvailableStatus = safetext.ConditionStatus(cond.Status)
		}
	}
	if ts := d.Spec.Template.Metadata.Annotations.restartedAt; ts != "" {
		if t, err := time.Parse(time.RFC3339, safetext.Clean(ts, 40)); err == nil {
			f.RestartedAt = t.UTC()
		}
	}
	return f
}

func reloadMechanism(d deployment) connectors.ReloadMechanism {
	meta, tmpl := d.Metadata.Annotations, d.Spec.Template.Metadata.Annotations
	switch {
	case meta.reloader || tmpl.reloader || tmpl.lastReloaded:
		return connectors.ReloadReloaderAnnotation
	case tmpl.checksum:
		return connectors.ReloadChecksumAnnotation
	}
	return connectors.ReloadNoneDetected
}

// buildFacts fills the facts and returns the current ReplicaSet: the
// owned one whose revision equals the Deployment's revision.
func buildFacts(d deployment, rss []replicaSet) (connectors.RolloutFacts, *replicaSet) {
	f := deploymentFacts(d)
	var current *replicaSet
	for i := range rss {
		rs := &rss[i]
		if !rs.ownedBy(d.Metadata.UID) {
			continue
		}
		f.OwnedReplicaSets++
		rev := safetext.Revision(rs.Metadata.Annotations.revision)
		if f.DeploymentRevision != "" && rev == f.DeploymentRevision {
			current = rs
		}
	}
	if current != nil {
		f.CurrentReplicaSetCreatedAt = current.Metadata.CreationTimestamp.UTC()
		f.CurrentReplicaSetAvailable = nonNeg(current.Status.AvailableReplicas)
	}
	return f, current
}

func trigger(notBefore, anchor time.Time, f connectors.RolloutFacts, current *replicaSet) connectors.RolloutTrigger {
	switch {
	case notBefore.IsZero():
		return connectors.TriggerNotChecked
	case current != nil && current.Metadata.CreationTimestamp.After(anchor):
		return connectors.TriggerReplicaSetAfterChange
	case !f.RestartedAt.IsZero() && f.RestartedAt.After(anchor):
		return connectors.TriggerAnnotationAfterChange
	case !f.RestartedAt.IsZero():
		return connectors.TriggerAnnotationBeforeChange
	}
	return connectors.TriggerNoRolloutSinceChange
}

// complete is kubectl rollout status's rule, plus the current
// ReplicaSet being fully available and the Progressing reason.
func complete(f connectors.RolloutFacts, current *replicaSet) bool {
	return current != nil &&
		f.ObservedGeneration >= f.Generation &&
		f.UpdatedReplicas == f.SpecReplicas &&
		f.Replicas == f.UpdatedReplicas &&
		f.AvailableReplicas == f.UpdatedReplicas &&
		f.CurrentReplicaSetAvailable >= f.SpecReplicas &&
		f.ProgressingReason == "NewReplicaSetAvailable"
}

// ceilSecond rounds t up to the next whole second. Kubernetes
// timestamps have second precision, so "strictly after the change"
// means strictly after the change rounded up; an equal timestamp never
// counts.
func ceilSecond(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	if tr := t.Truncate(time.Second); !tr.Equal(t) {
		return tr.Add(time.Second)
	}
	return t
}

func nonNeg(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
