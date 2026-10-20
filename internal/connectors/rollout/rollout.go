// Package rollout is the read-only connector for workload rollout
// status: one apps/v1 Deployment and the ReplicaSets it owns.
//
// Each Observe call is one snapshot: a GET of the Deployment and a
// bounded, label-selected LIST of ReplicaSets in its namespace. It reads
// no pods, no logs, no events and never a Secret. It proposes a stage
// outcome by the rules of ADR 0001 section 2.3 and returns its facts in
// the shared evidence model. It never sets a linkage: the loop derives
// it from the facts, and for a rollout it is at most time_ordered.
package rollout

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/kube"
	"github.com/secrets-bridge/gateway/internal/safetext"
)

// ReplicaSet list paging: pages of listPageSize, at most listMaxPages
// (runtime design 3.4: limit=50, stop after 200 items).
const (
	listPageSize = 50
	listMaxPages = 4
)

// Defaults Kubernetes applies when the field is unset.
const (
	defaultReplicas         = 1
	defaultProgressDeadline = 600
)

// Rollout triggers (evidence schema rolloutFacts.rollout_trigger).
const (
	triggerAnnotationAfter  = "pod_template_annotation_after_change"
	triggerAnnotationBefore = "pod_template_annotation_before_change"
	triggerRSCreated        = "replicaset_created_after_change"
	triggerRSBumped         = "replicaset_revision_bumped_after_change"
	triggerNone             = "no_rollout_since_change"
)

// Reload mechanisms (evidence schema rolloutFacts.reload_mechanism).
const (
	reloadReloader = "reloader_annotation"
	reloadChecksum = "checksum_annotation"
	reloadNone     = "none_detected"
)

type apiClient interface {
	Get(ctx context.Context, apiPath string, query url.Values, out any) (kube.Info, error)
	kubeconn.Reviewer
}

// Connector observes Deployment rollouts in its allowed namespaces.
type Connector struct {
	name       string
	namespaces []string
	targets    map[string]Target
	order      []string
	api        apiClient
	opts       kubeconn.Options
}

func newConnector(name string, s Settings, api apiClient, opts kubeconn.Options) *Connector {
	c := &Connector{
		name:       name,
		namespaces: append([]string(nil), s.Namespaces...),
		targets:    make(map[string]Target, len(s.Targets)),
		api:        api,
		opts:       opts,
	}
	for _, t := range s.Targets {
		c.targets[t.ID] = t
		c.order = append(c.order, t.ID)
	}
	return c
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Kind implements connectors.Connector.
func (c *Connector) Kind() connectors.Kind { return connectors.KindRollout }

// Targets implements connectors.Connector. Namespace and Name are for
// display in the catalog only.
func (c *Connector) Targets() []connectors.TargetInfo {
	out := make([]connectors.TargetInfo, 0, len(c.order))
	for _, id := range c.order {
		t := c.targets[id]
		out = append(out, connectors.TargetInfo{ID: t.ID, Namespace: t.Namespace, Name: t.Deployment})
	}
	return out
}

// Check implements connectors.Connector with the boot self-check of
// runtime design 5.3 for every allowed namespace. A write grant on
// deployments or replicasets is over-privilege, like any grant on secrets.
func (c *Connector) Check(ctx context.Context) error {
	return kubeconn.SelfCheck(ctx, c.api, c.namespaces, requiredAccess)
}

// Observe implements connectors.Connector.
func (c *Connector) Observe(ctx context.Context, target connectors.Target) (connectors.Observation, error) {
	now := c.opts.Clock()
	offsets := kubeconn.NewOffsetTracker(now)
	obs := connectors.Observation{
		Connector: c.name,
		Kind:      connectors.KindRollout,
		TargetID:  target.ID,
		Stage:     connectors.StageWorkloadRollout,
	}
	finish := func() (connectors.Observation, error) {
		obs.ObservedAt = now().UTC()
		obs.APIServerOffset, obs.APIServerOffsetKnown = offsets.Offset()
		return obs, nil
	}
	fail := func(code contract.ErrorCode) (connectors.Observation, error) {
		obs.Outcome = connectors.OutcomeError
		obs.Evidence = contract.StageEvidence{ErrorCode: code, Confidence: contract.ConfidenceNone}
		return finish()
	}

	t, ok := c.targets[target.ID]
	if !ok || target.NotBefore.IsZero() {
		// The registry refuses unknown targets before this point, and
		// the loop always sets a bound. Neither is readable as evidence.
		return fail(contract.ErrorInternal)
	}

	depPath, err := kube.ResourcePath("apps", "v1", t.Namespace, "deployments", t.Deployment)
	if err != nil {
		return fail(contract.ErrorInternal)
	}
	var dep deployment
	info, err := c.api.Get(ctx, depPath, nil, &dep)
	offsets.Note(info)
	if err != nil {
		return fail(kube.ErrorCode(err))
	}
	selector, ok := dep.Spec.Selector.String()
	if !ok || dep.Metadata.UID == "" {
		// apps/v1 requires a non-empty selector; anything else cannot be
		// turned into a safe label query.
		return fail(contract.ErrorInternal)
	}
	rss, truncated, err := c.listReplicaSets(ctx, t.Namespace, selector, offsets)
	if err != nil {
		return fail(kube.ErrorCode(err))
	}
	if truncated {
		// Non-terminal: the control plane looks again.
		return fail(contract.ErrorResponseTooLarge)
	}

	facts, current := buildFacts(dep, rss)
	mode := dep.Spec.Template.Spec.consumptionMode(target.Change.ESOTargetName)
	facts.ConsumptionMode = mode
	bound := offsets.Bound(target.NotBefore)
	facts.RolloutTrigger = trigger(bound, facts, current, target.Change.Baseline, dep)

	outcome, caveats, conf := decide(facts, target.Change)
	obs.Outcome = outcome
	obs.Evidence = contract.StageEvidence{
		Resource:   resource(t, dep),
		Facts:      &facts,
		Confidence: conf,
		Caveats:    caveats,
	}
	return finish()
}

// decide applies the workload_rollout rules of ADR 0001 section 2.3 to
// the facts. It never claims more than the facts show: observed needs a
// qualifying rollout that follows the ESO refresh when the task expects
// one, and a complete rollout by the kubectl rules.
func decide(f contract.RolloutFacts, ch connectors.Change) (contract.Outcome, []contract.Caveat, contract.Confidence) {
	cav := []contract.Caveat{}
	add := func(c contract.Caveat) { cav = append(cav, c) }
	if f.ObservedGeneration < f.Generation {
		add(contract.CaveatGenerationNotObserved)
	}

	switch {
	case f.SpecReplicas == 0:
		add(contract.CaveatZeroReplicas)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.Paused != nil && *f.Paused:
		add(contract.CaveatRolloutPaused)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.ConsumptionMode == modeSubpathVolume:
		add(contract.CaveatSubpathMountNotRefreshed)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	}

	// A rollout qualifies only after the ESO refresh that fetched the
	// change, when the task expects eso_sync (ADR 0001 section 2.2 step
	// 3). Without an observed refresh in this pass it cannot qualify.
	esoOrdered := !ch.ESOExpected || !ch.ESORefreshTime.IsZero()
	qualifying := esoOrdered && (f.RolloutTrigger == triggerRSCreated || f.RolloutTrigger == triggerRSBumped)
	if f.RolloutTrigger == triggerRSBumped {
		add(contract.CaveatReplicaSetReused)
	}

	if qualifying {
		switch {
		case f.ProgressingReason == "ProgressDeadlineExceeded":
			return contract.OutcomeFailed, cav, contract.ConfidenceMedium
		case complete(f):
			return contract.OutcomeObserved, cav, contract.ConfidenceMedium
		}
		add(contract.CaveatRolloutInProgress)
		return contract.OutcomeNotObserved, cav, contract.ConfidenceLow
	}

	noReload := f.ReloadMechanism == reloadNone
	switch {
	case f.ConsumptionMode == modeVolume && noReload:
		// The kubelet refreshes mounted files without a rollout, and
		// nothing in Deployment or ReplicaSet status shows that.
		add(contract.CaveatVolumeRefreshNotObservable)
		return contract.OutcomeNotApplicable, cav, contract.ConfidenceLow
	case (f.ConsumptionMode == modeEnv || f.ConsumptionMode == modeMixed) && noReload:
		add(contract.CaveatReloadMechanismUnknown)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.ConsumptionMode == modeUnknown && !ch.ESOExpected && noReload:
		// No ESO stage names the Secret, so the mode cannot be told; and
		// nothing is configured to restart the pods either way.
		add(contract.CaveatReloadMechanismUnknown)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.ConsumptionMode == modeNotReferenced:
		// The pod template does not reference the ExternalSecret target,
		// so no rollout of this Deployment can carry the change.
		add(contract.CaveatRolloutNotTriggeredByChange)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	}
	add(contract.CaveatRolloutNotTriggeredByChange)
	if f.RolloutTrigger == triggerAnnotationAfter {
		// restartedAt is after the bound but no ReplicaSet is: the
		// clocks disagree or the controller has not caught up.
		add(contract.CaveatClockSkewSuspected)
	}
	return contract.OutcomeNotObserved, cav, contract.ConfidenceLow
}

func (c *Connector) listReplicaSets(ctx context.Context, ns, selector string, offsets *kubeconn.OffsetTracker) ([]replicaSet, bool, error) {
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
		info, err := c.api.Get(ctx, p, q, &page)
		offsets.Note(info)
		if err != nil {
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

func resource(t Target, d deployment) *contract.Resource {
	r := &contract.Resource{APIVersion: "apps/v1", Kind: "Deployment", Namespace: t.Namespace, Name: t.Deployment}
	if contract.ValidUUID(d.Metadata.UID) {
		r.UID = d.Metadata.UID
	}
	if rv := safetext.Token(d.Metadata.ResourceVersion, 64, resourceVersionPattern, ""); rv != "" {
		r.ResourceVersion = rv
	}
	g := nonNeg(d.Metadata.Generation)
	r.Generation = &g
	return r
}

func deploymentFacts(d deployment) contract.RolloutFacts {
	spec := int64(defaultReplicas)
	if d.Spec.Replicas != nil {
		spec = nonNeg(*d.Spec.Replicas)
	}
	pds := int64(defaultProgressDeadline)
	if d.Spec.ProgressDeadlineSeconds != nil {
		pds = nonNeg(*d.Spec.ProgressDeadlineSeconds)
	}
	paused := d.Spec.Paused
	ptr := func(n int64) *int64 { v := nonNeg(n); return &v }
	f := contract.RolloutFacts{
		Generation:              nonNeg(d.Metadata.Generation),
		ObservedGeneration:      nonNeg(d.Status.ObservedGeneration),
		SpecReplicas:            spec,
		Paused:                  &paused,
		ProgressDeadlineSeconds: &pds,
		Replicas:                ptr(d.Status.Replicas),
		UpdatedReplicas:         ptr(d.Status.UpdatedReplicas),
		ReadyReplicas:           ptr(d.Status.ReadyReplicas),
		AvailableReplicas:       ptr(d.Status.AvailableReplicas),
		UnavailableReplicas:     ptr(d.Status.UnavailableReplicas),
		DeploymentRevision:      safetext.Revision(d.Metadata.Annotations.revision),
		ReloadMechanism:         reloadMechanism(d),
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
	return f
}

func reloadMechanism(d deployment) string {
	meta, tmpl := d.Metadata.Annotations, d.Spec.Template.Metadata.Annotations
	switch {
	case meta.reloader || tmpl.reloader || tmpl.lastReloaded:
		return reloadReloader
	case tmpl.checksum:
		return reloadChecksum
	}
	return reloadNone
}

// buildFacts fills the facts and returns the current ReplicaSet: the
// owned one whose revision equals the Deployment's revision, or the
// owned one with the highest revision when the Deployment has none.
func buildFacts(d deployment, rss []replicaSet) (contract.RolloutFacts, *replicaSet) {
	f := deploymentFacts(d)
	var current *replicaSet
	best := int64(-1)
	for i := range rss {
		rs := &rss[i]
		if !rs.ownedBy(d.Metadata.UID) {
			continue
		}
		rev := safetext.Revision(rs.Metadata.Annotations.revision)
		if f.DeploymentRevision != "" {
			if rev == f.DeploymentRevision {
				current = rs
			}
			continue
		}
		if n, err := strconv.ParseInt(rev, 10, 64); err == nil && n > best {
			best, current = n, rs
		}
	}
	if current != nil && !current.Metadata.CreationTimestamp.IsZero() {
		ts := current.Metadata.CreationTimestamp.UTC()
		f.NewestReplicaSetCreatedAt = &ts
	}
	return f, current
}

// trigger is the qualifying-rollout rule of runtime design 3.4, judged
// against bound (the rollout NotBefore plus the API server offset):
//  1. the current ReplicaSet was created strictly after bound;
//  2. otherwise the Deployment revision is greater than the baseline the
//     control plane copied from the earliest pass with eso_sync observed
//     (a rollback or a template that reuses an older ReplicaSet);
//  3. otherwise the restartedAt annotation, when present, is reported as
//     before or after the bound; it is never a qualifying rollout.
func trigger(bound time.Time, f contract.RolloutFacts, current *replicaSet, baseline *contract.RolloutBaseline, d deployment) string {
	if current != nil && current.Metadata.CreationTimestamp.After(bound) {
		return triggerRSCreated
	}
	if baseline != nil {
		cur, err1 := strconv.ParseInt(f.DeploymentRevision, 10, 64)
		base, err2 := strconv.ParseInt(baseline.DeploymentRevision, 10, 64)
		if err1 == nil && err2 == nil && cur > base {
			return triggerRSBumped
		}
	}
	if ts := d.Spec.Template.Metadata.Annotations.restartedAt; ts != "" {
		if rt, err := time.Parse(time.RFC3339, safetext.Clean(ts, 40)); err == nil {
			if rt.After(bound) {
				return triggerAnnotationAfter
			}
			return triggerAnnotationBefore
		}
	}
	return triggerNone
}

// complete is the kubectl rollout status rule (ADR 0001 section 2.2
// step 3). .status.replicas alone is never the desired count.
func complete(f contract.RolloutFacts) bool {
	if f.UpdatedReplicas == nil || f.Replicas == nil || f.AvailableReplicas == nil {
		return false
	}
	return f.ObservedGeneration >= f.Generation &&
		*f.UpdatedReplicas == f.SpecReplicas &&
		*f.Replicas == *f.UpdatedReplicas &&
		*f.AvailableReplicas == *f.UpdatedReplicas
}

func nonNeg(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}
