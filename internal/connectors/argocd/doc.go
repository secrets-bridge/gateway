// Package argocd is the Gateway's read-only ArgoCD connector.
//
// The HTTP client is ported from the control plane's api/pkg/argocd
// client, and the outcome mapping from the worker's GitOps poller
// (worker/internal/sweepers/gitops_poller.go, decideTerminalState). Both
// are adapted to the Gateway rules:
//
//   - Read-only. The client is built on internal/readonly with a policy
//     that admits exactly GET <base>/api/v1/applications/{name}, whose
//     only allowed query key is appNamespace, GET
//     <base>/api/v1/session/userinfo and the can-i probe paths for the
//     self-check, and the application list with projects required (each
//     an allowed AppProject) and fields only with the fixed projection.
//     Release 1 never sends the list. resource-tree, managed-resources,
//     manifests and the refresh query are refused in the transport. No
//     proxy is used.
//   - Negative probe. The self-check asks can-i for every write action
//     on every allowed AppProject; a yes is over-privilege and a failed
//     probe fails closed.
//   - Bound settings only. The base URL, token file, CA file, allowed
//     AppProjects and the target-to-Application map come from the local
//     connectors file. A task names a target id and nothing else.
//   - Token from a file, read at use time and re-read when the file
//     changes. It is never logged or part of an error.
//   - Context only. Results use the shared contract evidence model with
//     stage argocd_context: at most observed with confidence low, always
//     the argocd_health_not_proof caveat, never failed or
//     not_applicable. The loop sets linkage none. A read failure is a
//     retryable error with a schema error code.
//   - The uid is the identity. The first successful read of a target
//     records metadata.uid in memory; a later answer with another uid
//     under the same name is an error observation until the Gateway is
//     restarted. Nothing else is kept between reads.
//   - Metadata only. Health and operation messages, manifests, sources
//     and Helm values are never decoded.
package argocd
