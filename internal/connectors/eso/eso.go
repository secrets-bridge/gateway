// Package eso is the read-only connector for External Secrets Operator
// ExternalSecret status.
//
// Each Observe call is one GET of one ExternalSecret by name, in
// external-secrets.io/v1, falling back to v1beta1 when v1 is not served.
// The response is decoded into a projected struct: the Ready condition
// without its message, refreshTime, syncedResourceVersion, the refresh
// interval and policy, the target Secret name, and the remote keys and
// pinned versions, which are compared with the task's change marker
// inside the Gateway and never reported. The target Kubernetes Secret
// is never read.
//
// The connector proposes an eso_sync outcome by ADR 0001 section 2.3.
// It never sets a linkage: the loop derives version_pinned only from
// remote_version_pin = matches_expected and a provider version the agent
// reported, and time_ordered otherwise.
package eso

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/secrets-bridge/gateway/internal/connectors"
	"github.com/secrets-bridge/gateway/internal/connectors/kubeconn"
	"github.com/secrets-bridge/gateway/internal/contract"
	"github.com/secrets-bridge/gateway/internal/kube"
	"github.com/secrets-bridge/gateway/internal/safetext"
)

// Facts enum values (evidence schema esoFacts).
const (
	refMatch         = "match"
	refMismatch      = "mismatch"
	refNotChecked    = "not_checked"
	refExtractOrFind = "extract_or_find"

	pinNone    = "none"
	pinMatches = "matches_expected"
	pinOther   = "other_version"
)

// awsCurrentStage is the AWS Secrets Manager staging label that always
// names the current version. A remoteRef.version equal to it follows the
// current version and is not a pin (verify for the supported ESO range).
const awsCurrentStage = "AWSCURRENT"

var (
	resourceVersionPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
	syncedRVPattern        = regexp.MustCompile(`^[0-9A-Za-z-]{1,128}$`)
)

type apiClient interface {
	Get(ctx context.Context, apiPath string, query url.Values, out any) (kube.Info, error)
	kubeconn.Reviewer
}

// Connector observes ExternalSecrets in its allowed namespaces.
type Connector struct {
	name       string
	namespaces []string
	targets    map[string]Target
	order      []string
	api        apiClient
	opts       kubeconn.Options

	mu      sync.Mutex
	version string // last served version; v1 until v1 is not served
}

func newConnector(name string, s Settings, api apiClient, opts kubeconn.Options) *Connector {
	c := &Connector{
		name:       name,
		namespaces: append([]string(nil), s.Namespaces...),
		targets:    make(map[string]Target, len(s.Targets)),
		api:        api,
		opts:       opts,
		version:    versionV1,
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
func (c *Connector) Kind() connectors.Kind { return connectors.KindESO }

// Targets implements connectors.Connector. Namespace and Name are for
// display in the catalog only.
func (c *Connector) Targets() []connectors.TargetInfo {
	out := make([]connectors.TargetInfo, 0, len(c.order))
	for _, id := range c.order {
		t := c.targets[id]
		out = append(out, connectors.TargetInfo{ID: t.ID, Namespace: t.Namespace, Name: t.ExternalSecret})
	}
	return out
}

// Check implements connectors.Connector with the boot self-check of
// runtime design 5.3 for every allowed namespace. A write grant on
// externalsecrets is over-privilege, like any grant on secrets.
func (c *Connector) Check(ctx context.Context) error {
	return kubeconn.SelfCheck(ctx, c.api, c.namespaces, requiredAccess)
}

// externalSecret is the projected ExternalSecret. Fields that are not
// declared (condition messages, templates, labels, annotations, store
// references and everything else) are never decoded.
type externalSecret struct {
	Metadata struct {
		UID             string `json:"uid"`
		ResourceVersion string `json:"resourceVersion"`
		Generation      int64  `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		RefreshInterval *string `json:"refreshInterval"`
		RefreshPolicy   string  `json:"refreshPolicy"`
		Target          struct {
			Name string `json:"name"`
		} `json:"target"`
		Data []struct {
			RemoteRef struct {
				Key     string `json:"key"`
				Version string `json:"version"`
			} `json:"remoteRef"`
		} `json:"data"`
		DataFrom []struct {
			Extract *struct {
				Key     string `json:"key"`
				Version string `json:"version"`
			} `json:"extract"`
			Find      *struct{} `json:"find"`
			SourceRef *struct{} `json:"sourceRef"`
		} `json:"dataFrom"`
	} `json:"spec"`
	Status struct {
		RefreshTime           *time.Time `json:"refreshTime"`
		SyncedResourceVersion string     `json:"syncedResourceVersion"`
		Conditions            []struct {
			Type               string     `json:"type"`
			Status             string     `json:"status"`
			Reason             string     `json:"reason"`
			LastTransitionTime *time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
	} `json:"status"`
}

// Observe implements connectors.Connector.
func (c *Connector) Observe(ctx context.Context, target connectors.Target) (connectors.Observation, error) {
	now := c.opts.Clock()
	offsets := kubeconn.NewOffsetTracker(now)
	obs := connectors.Observation{
		Connector: c.name,
		Kind:      connectors.KindESO,
		TargetID:  target.ID,
		Stage:     connectors.StageESOSync,
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
		return fail(contract.ErrorInternal)
	}
	es, version, err := c.read(ctx, t, offsets)
	if err != nil {
		return fail(kube.ErrorCode(err))
	}

	facts := buildFacts(es, t, target.Change)
	outcome, caveats, conf := decide(facts, es, target, offsets.Bound(target.NotBefore), now())
	obs.Outcome = outcome
	obs.Evidence = contract.StageEvidence{
		Resource:   resource(t, es, version),
		Facts:      &facts,
		Confidence: conf,
		Caveats:    caveats,
	}
	return finish()
}

// read GETs the ExternalSecret in the last served version and falls back
// to the other version when the API server says that group version is
// not served (a 404 without a NotFound Status). The served version is
// remembered; it is boot-like discovery state, not observation state.
func (c *Connector) read(ctx context.Context, t Target, offsets *kubeconn.OffsetTracker) (externalSecret, string, error) {
	c.mu.Lock()
	first := c.version
	c.mu.Unlock()
	order := []string{first, versionV1beta1}
	if first == versionV1beta1 {
		order = []string{versionV1beta1, versionV1}
	}
	var lastErr error
	for _, v := range order {
		p, err := kube.ResourcePath("external-secrets.io", v, t.Namespace, "externalsecrets", t.ExternalSecret)
		if err != nil {
			return externalSecret{}, "", err
		}
		var es externalSecret
		info, err := c.api.Get(ctx, p, nil, &es)
		offsets.Note(info)
		if err == nil {
			c.mu.Lock()
			c.version = v
			c.mu.Unlock()
			return es, v, nil
		}
		lastErr = err
		if kube.ErrorCode(err) != contract.ErrorAPIVersionNotServed {
			return externalSecret{}, "", err
		}
	}
	return externalSecret{}, "", lastErr
}

func resource(t Target, es externalSecret, version string) *contract.Resource {
	r := &contract.Resource{
		APIVersion: "external-secrets.io/" + version,
		Kind:       "ExternalSecret",
		Namespace:  t.Namespace,
		Name:       t.ExternalSecret,
	}
	if contract.ValidUUID(es.Metadata.UID) {
		r.UID = es.Metadata.UID
	}
	if rv := safetext.Token(es.Metadata.ResourceVersion, 64, resourceVersionPattern, ""); rv != "" {
		r.ResourceVersion = rv
	}
	g := max(es.Metadata.Generation, 0)
	r.Generation = &g
	return r
}

func buildFacts(es externalSecret, t Target, ch connectors.Change) contract.ESOFacts {
	f := contract.ESOFacts{ReadyStatus: "Unknown"}
	for _, cond := range es.Status.Conditions {
		if cond.Type != "Ready" {
			continue
		}
		if st := safetext.ConditionStatus(cond.Status); st != "" {
			f.ReadyStatus = st
		}
		f.ReadyReason = safetext.ConditionReason(cond.Reason)
		if cond.LastTransitionTime != nil && !cond.LastTransitionTime.IsZero() {
			ts := cond.LastTransitionTime.UTC()
			f.ReadyLastTransitionTime = &ts
		}
	}
	if rt := es.Status.RefreshTime; rt != nil && !rt.IsZero() {
		ts := rt.UTC()
		f.RefreshTime = &ts
	}
	if srv := safetext.Token(es.Status.SyncedResourceVersion, 128, syncedRVPattern, ""); srv != "" {
		f.SyncedResourceVersion = srv
		// syncedResourceVersion is "<generation>-<hash of metadata>" in
		// the ESO versions checked; anything else is reported as false
		// (verify for the supported range).
		match := strings.HasPrefix(srv, strconv.FormatInt(es.Metadata.Generation, 10)+"-")
		f.ObservedGenerationMatches = &match
	}
	if secs, ok := refreshSeconds(es.Spec.RefreshInterval); ok {
		f.RefreshIntervalSeconds = &secs
	}
	f.RemoteRefMatch, f.RemoteVersionPin = remoteRef(es, ch)
	name := es.Spec.Target.Name
	if name == "" {
		name = t.ExternalSecret
	}
	if kube.ValidObjectName(name) {
		f.TargetSecretName = name
	}
	return f
}

// refreshSeconds converts spec.refreshInterval (a Go duration string such
// as "1h0m0s"; "0" disables timer refreshes). Unset or unparsable gives
// false, and no deadline judgement is made from it.
func refreshSeconds(raw *string) (int64, bool) {
	if raw == nil {
		return 0, false
	}
	d, err := time.ParseDuration(strings.TrimSpace(*raw))
	if err != nil || d < 0 || d > 1000000000*time.Second {
		return 0, false
	}
	return int64(d / time.Second), true
}

// remoteRef compares the ExternalSecret's remote keys with the change
// marker's key, and the pinned versions of the matching entries with
// the agent-reported provider version. Only the enum results leave this
// function; keys and versions are never reported or logged.
func remoteRef(es externalSecret, ch connectors.Change) (match, pin string) {
	if ch.RemoteKey == "" {
		return refNotChecked, pinNone
	}
	var versions []string
	matched, findLike := false, false
	for _, d := range es.Spec.Data {
		if d.RemoteRef.Key == ch.RemoteKey {
			matched = true
			versions = append(versions, d.RemoteRef.Version)
		}
	}
	for _, d := range es.Spec.DataFrom {
		switch {
		case d.Extract != nil && d.Extract.Key == ch.RemoteKey:
			matched = true
			versions = append(versions, d.Extract.Version)
		case d.Find != nil, d.SourceRef != nil:
			findLike = true
		}
	}
	switch {
	case matched:
		return refMatch, pinFor(versions, ch.ProviderVersionID)
	case findLike:
		return refExtractOrFind, pinNone
	}
	return refMismatch, pinNone
}

// pinFor is matches_expected only when every matching entry pins the
// reported version, other_version when any entry pins something else,
// and none otherwise.
func pinFor(versions []string, expected string) string {
	pinned, unpinned := 0, 0
	for _, v := range versions {
		switch {
		case v == "" || v == awsCurrentStage:
			unpinned++
		case expected != "" && (v == expected || v == "uuid/"+expected):
			pinned++
		default:
			return pinOther
		}
	}
	if pinned > 0 && unpinned == 0 {
		return pinMatches
	}
	return pinNone
}

// decide applies the eso_sync rules of ADR 0001 section 2.3. bound is
// the task's NotBefore (executed_at plus skew) plus the API server
// offset, rounded up to a whole second.
func decide(f contract.ESOFacts, es externalSecret, target connectors.Target, bound, now time.Time) (contract.Outcome, []contract.Caveat, contract.Confidence) {
	cav := []contract.Caveat{}
	add := func(c contract.Caveat) { cav = append(cav, c) }
	ch := target.Change

	switch {
	case f.RemoteRefMatch == refNotChecked:
		add(contract.CaveatRemoteRefNotChecked)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.RemoteRefMatch == refMismatch:
		add(contract.CaveatRemoteRefMismatch)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.RemoteRefMatch == refExtractOrFind:
		add(contract.CaveatDataFromExtractOrFind)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	case f.RemoteVersionPin == pinOther:
		add(contract.CaveatRemoteVersionPinnedOther)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	}

	if f.ReadyStatus == "False" && f.ReadyLastTransitionTime != nil && f.ReadyLastTransitionTime.After(bound) {
		return contract.OutcomeFailed, cav, contract.ConfidenceMedium
	}

	refreshed := f.RefreshTime != nil && f.RefreshTime.After(bound)
	if f.ReadyStatus == "True" && f.ReadyReason == "SecretSynced" && refreshed {
		if ch.ProviderVersionID == "" {
			add(contract.CaveatProviderVersionMissing)
		}
		if f.RemoteVersionPin == pinMatches && ch.ProviderVersionID != "" {
			return contract.OutcomeObserved, cav, contract.ConfidenceHigh
		}
		add(contract.CaveatESOStatusHasNoProviderVersion)
		return contract.OutcomeObserved, cav, contract.ConfidenceMedium
	}

	if !refreshed && refreshCannotHappen(f, es, ch.DeadlineAt, now) {
		add(contract.CaveatRefreshIntervalExceedsDeadline)
		return contract.OutcomeUnverifiable, cav, contract.ConfidenceLow
	}

	switch {
	case f.RefreshTime == nil || !f.RefreshTime.After(ch.ExecutedAt):
		add(contract.CaveatRefreshBeforeChange)
	case !refreshed:
		add(contract.CaveatRefreshTimeWithinSkew)
	}
	return contract.OutcomeNotObserved, cav, contract.ConfidenceLow
}

// refreshCannotHappen reports that no timer refresh can land before the
// deadline: refreshInterval is 0, the refresh policy is not periodic,
// or the next refresh after the last one is past the deadline. An unset
// interval is not judged.
func refreshCannotHappen(f contract.ESOFacts, es externalSecret, deadline, now time.Time) bool {
	switch es.Spec.RefreshPolicy {
	case "", "Periodic":
	default:
		// OnChange, CreatedOnce or a policy this build does not know:
		// refreshTime does not move on a timer (verify per ESO version).
		return true
	}
	if f.RefreshIntervalSeconds == nil || deadline.IsZero() {
		return false
	}
	interval := time.Duration(*f.RefreshIntervalSeconds) * time.Second
	if interval == 0 {
		return true
	}
	last := now
	if f.RefreshTime != nil {
		last = *f.RefreshTime
	}
	return last.Add(interval).After(deadline)
}
