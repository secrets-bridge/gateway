package connectors

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/secrets-bridge/gateway/internal/contract"
)

// ReservedTargetIDPrefix starts every discovered target id (ADR 0002
// condition C3). A static target id may not start with it.
const ReservedTargetIDPrefix = "d-"

// Errors of discovery.
var (
	// ErrCatalogTooLarge: a discovery run hit a cap (the list byte or
	// count cap of C1, or the E8 body cap). The run is refused whole;
	// nothing is truncated and nothing is uploaded (local code
	// catalog_too_large).
	ErrCatalogTooLarge = errors.New("connectors: catalog_too_large: discovery run over a cap; nothing uploaded")
	// ErrDiscoveryOff: the connector has no discovery, or it is off.
	ErrDiscoveryOff = errors.New("connectors: discovery is not enabled on this connector")
	// ErrTargetSnapshotStale: a task named a discovered target while the
	// replica has no usable snapshot. Nothing was read.
	ErrTargetSnapshotStale = errors.New("connectors: no usable discovery snapshot for a discovered target")
)

// Scope is what an Argo CD connector reports for C6: its scope digest
// and the inputs the control plane can check it against. It never holds
// the base URL.
type Scope struct {
	ScopeDigest    string
	EndpointDigest string
	// AllowedProjects is sorted and unique.
	AllowedProjects  []string
	DiscoveryEnabled bool
	// IntervalSeconds is discovery.interval in whole seconds, set only
	// when DiscoveryEnabled.
	IntervalSeconds int
	IdentityMode    string
}

// DiscoveryRun is the result of one discovery run: the validated,
// probed targets that may enter the snapshot, sorted by target id, and
// the counts of dropped and deferred items. It holds raw uids and real
// names; it is sealed, never logged.
type DiscoveryRun struct {
	Targets  []contract.SnapshotTarget
	Rejected int
	Deferred int
}

// Snapshot is an opened, accepted snapshot a connector resolves
// discovered targets through.
type Snapshot struct {
	Generation int64
	// DiscoveredAt is discovered_at on the sealing replica's clock.
	DiscoveredAt time.Time
	Targets      []contract.SnapshotTarget
}

// TargetStatus says how a replica would resolve a target id now.
type TargetStatus int

// Target statuses.
const (
	// TargetUnbound: no such target (unbound_target).
	TargetUnbound TargetStatus = iota
	// TargetBound: a static target, or a discovered target in a usable
	// snapshot.
	TargetBound
	// TargetSnapshotStale: a discovered target id on a connector with
	// discovery on, while the replica has no usable snapshot
	// (target_snapshot_stale).
	TargetSnapshotStale
)

// Discoverer is implemented by connectors that can discover their
// targets (the Argo CD connector). Every method is safe for concurrent
// use. A Discoverer with discovery off reports its Scope and nothing
// else.
type Discoverer interface {
	// Scope reports the C6 scope for gatewayID.
	Scope(gatewayID string) Scope
	// DiscoveryEnabled reports discovery.enabled.
	DiscoveryEnabled() bool
	// SnapshotMaxAge is discovery.snapshot_max_age.
	SnapshotMaxAge() time.Duration
	// Discover runs one discovery pass: the list reads, validation, id
	// derivation and the per-target probe of every new target until
	// probeBy. It returns ErrCatalogTooLarge over a cap, and wraps
	// ErrOverPrivileged or ErrPrivilegeUnproven when a probe answered
	// yes or failed. It never publishes anything.
	Discover(ctx context.Context, probeBy time.Time) (DiscoveryRun, error)
	// InstallSnapshot makes s the snapshot targets resolve through.
	InstallSnapshot(s Snapshot)
	// ClearSnapshot drops the snapshot: discovered targets are refused
	// with target_snapshot_stale until a new one is installed.
	ClearSnapshot()
	// SnapshotState reports the installed snapshot's generation and
	// whether it is usable now (present and within its maximum age).
	SnapshotState() (generation int64, usable bool)
	// SetBoundTargets replaces the bound target ids the control plane
	// reported for this connector (C2: bound targets are probed at each
	// recheck).
	SetBoundTargets(ids []string)
	// DiscoveredStatus reports how a d- target id resolves now.
	DiscoveredStatus(id string) TargetStatus
}

// Discoverer returns the connector bound under name as a Discoverer, if
// it is one.
func (r *Registry) Discoverer(name string) (Discoverer, bool) {
	c, err := r.Lookup(name)
	if err != nil {
		return nil, false
	}
	d, ok := c.(Discoverer)
	return d, ok
}

// DiscoveryConnectors returns the names of the connectors with
// discovery on, sorted.
func (r *Registry) DiscoveryConnectors() []string {
	var out []string
	for _, n := range r.Names() {
		if d, ok := r.byName[n].(Discoverer); ok && d.DiscoveryEnabled() {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// TargetStatus reports how a task's target would resolve now: a static
// target of the connector, a discovered target in a usable snapshot, a
// discovered target id while there is no usable snapshot, or nothing.
func (r *Registry) TargetStatus(name, targetID string) TargetStatus {
	if !ValidName(name) || !ValidName(targetID) {
		return TargetUnbound
	}
	if _, ok := r.targets[name][targetID]; ok {
		return TargetBound
	}
	d, ok := r.Discoverer(name)
	if !ok || !d.DiscoveryEnabled() || !strings.HasPrefix(targetID, ReservedTargetIDPrefix) {
		return TargetUnbound
	}
	return d.DiscoveredStatus(targetID)
}

// Discover runs one discovery pass through the connector bound under
// name. Like Observe, it refuses a connector whose last self-check did
// not pass (ErrConnectorUnverified), and a privilege finding of the run
// demotes the connector: a yes marks it over_privileged, a failed probe
// unverified.
func (r *Registry) Discover(ctx context.Context, name string, probeBy time.Time) (DiscoveryRun, error) {
	d, ok := r.Discoverer(name)
	if !ok || !d.DiscoveryEnabled() {
		return DiscoveryRun{}, ErrDiscoveryOff
	}
	if !r.isVerified(name) {
		return DiscoveryRun{}, fmt.Errorf("%w: connector %q", ErrConnectorUnverified, name)
	}
	run, err := d.Discover(ctx, probeBy)
	r.demote(name, err)
	if err != nil {
		return DiscoveryRun{}, err
	}
	return run, nil
}
