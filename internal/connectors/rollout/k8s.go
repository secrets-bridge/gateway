package rollout

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Projected API objects. The Gateway decodes the raw response straight
// into these structs, so container specs, env literals, volumes and
// every annotation outside the allowlist are dropped at decode time and
// never sit in a typed object.

type condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type deployment struct {
	Metadata struct {
		UID             string      `json:"uid"`
		ResourceVersion string      `json:"resourceVersion"`
		Generation      int64       `json:"generation"`
		Annotations     annotations `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas                *int64        `json:"replicas"`
		Paused                  bool          `json:"paused"`
		ProgressDeadlineSeconds *int64        `json:"progressDeadlineSeconds"`
		Selector                labelSelector `json:"selector"`
		Template                struct {
			Metadata struct {
				Annotations annotations `json:"annotations"`
			} `json:"metadata"`
			Spec podSpec `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64       `json:"observedGeneration"`
		Replicas            int64       `json:"replicas"`
		UpdatedReplicas     int64       `json:"updatedReplicas"`
		ReadyReplicas       int64       `json:"readyReplicas"`
		AvailableReplicas   int64       `json:"availableReplicas"`
		UnavailableReplicas int64       `json:"unavailableReplicas"`
		Conditions          []condition `json:"conditions"`
	} `json:"status"`
}

// podSpec holds only the Secret names the pod template references and
// whether a mount uses subPath. env[].value, args, command, images and
// every other field are not declared, so they are never decoded.
type podSpec struct {
	Containers     []container `json:"containers"`
	InitContainers []container `json:"initContainers"`
	Volumes        []volume    `json:"volumes"`
}

type container struct {
	EnvFrom []struct {
		SecretRef *struct {
			Name string `json:"name"`
		} `json:"secretRef"`
	} `json:"envFrom"`
	Env []struct {
		ValueFrom *struct {
			SecretKeyRef *struct {
				Name string `json:"name"`
			} `json:"secretKeyRef"`
		} `json:"valueFrom"`
	} `json:"env"`
	VolumeMounts []struct {
		Name        string   `json:"name"`
		SubPath     presence `json:"subPath"`
		SubPathExpr presence `json:"subPathExpr"`
	} `json:"volumeMounts"`
}

type volume struct {
	Name   string `json:"name"`
	Secret *struct {
		SecretName string `json:"secretName"`
	} `json:"secret"`
	Projected *struct {
		Sources []struct {
			Secret *struct {
				Name string `json:"name"`
			} `json:"secret"`
		} `json:"sources"`
	} `json:"projected"`
}

// presence records that a string field is set and non-empty, and drops
// its value.
type presence bool

func (p *presence) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil && s != "" {
		*p = true
	}
	return nil
}

// Consumption modes (evidence schema rolloutFacts.consumption_mode).
const (
	modeEnv           = "env"
	modeVolume        = "volume"
	modeSubpathVolume = "subpath_volume"
	modeMixed         = "mixed"
	modeNotReferenced = "not_referenced"
	modeUnknown       = "unknown"
)

// consumptionMode compares the Secret names the pod template references
// with target, the ExternalSecret spec.target.name read in the same
// pass. Names are compared here and never reported.
func (p podSpec) consumptionMode(target string) string {
	if target == "" {
		return modeUnknown
	}
	env := false
	vols := map[string]bool{}
	for _, v := range p.Volumes {
		if v.Secret != nil && v.Secret.SecretName == target {
			vols[v.Name] = true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil && src.Secret.Name == target {
					vols[v.Name] = true
				}
			}
		}
	}
	subpath := false
	for _, c := range append(append([]container(nil), p.Containers...), p.InitContainers...) {
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil && ef.SecretRef.Name == target {
				env = true
			}
		}
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && e.ValueFrom.SecretKeyRef.Name == target {
				env = true
			}
		}
		for _, m := range c.VolumeMounts {
			if vols[m.Name] && (bool(m.SubPath) || bool(m.SubPathExpr)) {
				subpath = true
			}
		}
	}
	switch {
	case subpath:
		// A subPath mount never refreshes until the pod restarts, so it
		// decides the mode even when env also references the Secret.
		return modeSubpathVolume
	case env && len(vols) > 0:
		return modeMixed
	case env:
		return modeEnv
	case len(vols) > 0:
		return modeVolume
	}
	return modeNotReferenced
}

type ownerRef struct {
	UID        string `json:"uid"`
	Controller *bool  `json:"controller"`
}

type replicaSet struct {
	Metadata struct {
		UID               string      `json:"uid"`
		CreationTimestamp time.Time   `json:"creationTimestamp"`
		Annotations       annotations `json:"annotations"`
		OwnerReferences   []ownerRef  `json:"ownerReferences"`
	} `json:"metadata"`
	Status struct {
		Replicas          int64 `json:"replicas"`
		AvailableReplicas int64 `json:"availableReplicas"`
	} `json:"status"`
}

type replicaSetList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []replicaSet `json:"items"`
}

func (r replicaSet) ownedBy(uid string) bool {
	for _, o := range r.Metadata.OwnerReferences {
		if o.UID == uid && o.Controller != nil && *o.Controller {
			return true
		}
	}
	return false
}

// Annotation keys the connector looks at. Verify the Reloader keys
// against the installed Reloader version.
const (
	annRevision        = "deployment.kubernetes.io/revision"
	annRestartedAt     = "kubectl.kubernetes.io/restartedAt"
	annReloaderAuto    = "reloader.stakater.com/auto"
	annReloaderSearch  = "reloader.stakater.com/search"
	annReloaderSecret  = "secret.reloader.stakater.com/reload"
	annReloaderSecAuto = "secret.reloader.stakater.com/auto"
	annReloaderLast    = "reloader.stakater.com/last-reloaded-from"
	annChecksumPrefix  = "checksum/"
)

// annotations keeps only the allowlisted annotations. Values are kept
// for the revision and restartedAt (a number and a timestamp) and
// reduced to a boolean for everything else. Reloader's
// last-reloaded-from value can carry a hash of Secret data, and
// last-applied-configuration can carry env literals: neither is kept.
type annotations struct {
	revision     string
	restartedAt  string
	reloader     bool
	checksum     bool
	lastReloaded bool
}

func (a *annotations) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	str := func(raw json.RawMessage) string {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return ""
		}
		return s
	}
	for k, raw := range m {
		switch {
		case k == annRevision:
			a.revision = str(raw)
		case k == annRestartedAt:
			a.restartedAt = str(raw)
		case k == annReloaderAuto || k == annReloaderSecAuto || k == annReloaderSearch:
			if str(raw) == "true" {
				a.reloader = true
			}
		case k == annReloaderSecret:
			if str(raw) != "" {
				a.reloader = true
			}
		case k == annReloaderLast:
			a.lastReloaded = true
		case strings.HasPrefix(k, annChecksumPrefix):
			a.checksum = true
		}
	}
	return nil
}

type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

var (
	labelKey   = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	labelValue = regexp.MustCompile(`^(([A-Za-z0-9][-A-Za-z0-9_.]{0,61})?[A-Za-z0-9])?$`)
)

const maxSelectorTerms = 32

// resourceVersionPattern is the schema k8sResourceVersion pattern.
var resourceVersionPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// String renders the selector in the label-selector query syntax. It
// returns false for an empty selector (which would match every
// ReplicaSet in the namespace) or for anything that is not valid label
// syntax, so a crafted Deployment cannot inject query syntax.
func (s labelSelector) String() (string, bool) {
	if len(s.MatchLabels)+len(s.MatchExpressions) == 0 || len(s.MatchLabels)+len(s.MatchExpressions) > maxSelectorTerms {
		return "", false
	}
	keys := make([]string, 0, len(s.MatchLabels))
	for k := range s.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	terms := make([]string, 0, len(keys)+len(s.MatchExpressions))
	for _, k := range keys {
		v := s.MatchLabels[k]
		if len(k) > 316 || !labelKey.MatchString(k) || !labelValue.MatchString(v) {
			return "", false
		}
		terms = append(terms, k+"="+v)
	}
	for _, e := range s.MatchExpressions {
		if len(e.Key) > 316 || !labelKey.MatchString(e.Key) || len(e.Values) > maxSelectorTerms {
			return "", false
		}
		for _, v := range e.Values {
			if !labelValue.MatchString(v) {
				return "", false
			}
		}
		switch e.Operator {
		case "In", "NotIn":
			if len(e.Values) == 0 {
				return "", false
			}
			vals := append([]string(nil), e.Values...)
			sort.Strings(vals)
			terms = append(terms, e.Key+" "+strings.ToLower(e.Operator)+" ("+strings.Join(vals, ",")+")")
		case "Exists":
			terms = append(terms, e.Key)
		case "DoesNotExist":
			terms = append(terms, "!"+e.Key)
		default:
			return "", false
		}
	}
	return strings.Join(terms, ","), true
}
