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
		UID         string      `json:"uid"`
		Generation  int64       `json:"generation"`
		Annotations annotations `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int64        `json:"replicas"`
		Paused   bool          `json:"paused"`
		Selector labelSelector `json:"selector"`
		Template struct {
			Metadata struct {
				Annotations annotations `json:"annotations"`
			} `json:"metadata"`
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
