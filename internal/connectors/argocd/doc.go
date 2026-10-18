// Package argocd is the Gateway's read-only ArgoCD connector.
//
// The HTTP client is ported from the control plane's api/pkg/argocd
// client, and the outcome mapping from the worker's GitOps poller
// (worker/internal/sweepers/gitops_poller.go, decideTerminalState). Both
// are adapted to the Gateway rules:
//
//   - Read-only. The client is built on internal/readonly, so only GET
//     leaves the process, and a path allowlist admits only
//     GET <base>/api/v1/applications/{name}. List, resource-tree,
//     managed-resources and manifests are refused in the transport.
//   - Bound settings only. The base URL, token file, CA file, allowed
//     AppProjects and the target-to-Application map come from the local
//     connectors file. A task names a target id and nothing else.
//   - Token from a file, read at use time and re-read when the file
//     changes. It is never logged or part of an error.
//   - Honest outcomes. Healthy and Synced is at most observed; ArgoCD
//     never reports verified, and every observation carries the
//     argocd_health_not_proof caveat.
//   - Metadata only. Health and operation messages, manifests, sources
//     and Helm values are never decoded.
package argocd
