# CLAUDE.md: secrets-bridge/gateway

Instructions for Claude Code and contributors working in this repo. For the whole platform, see https://secrets-bridge.io.

## What this repo is

The Secrets Bridge Gateway: an optional observation plane that runs inside a customer security boundary. It claims observation tasks from the control plane over outbound HTTPS, reads local integrations, and posts metadata-only evidence back. **The repo is in the design phase: implement nothing beyond what the approved architecture decision record covers.**

## Rules for this repo

- **Outbound only.** No inbound listener except the loopback health and metrics endpoint.
- **Read-only.** Never sync, roll back, patch or delete anything in ArgoCD, External Secrets Operator or Kubernetes.
- **No secret values.** Never read Kubernetes Secrets (no `get`, `list` or `watch` on `secrets` in RBAC, because `get` returns the values). Evidence comes from ExternalSecret status and Deployment or ReplicaSet rollout metadata. Never put values, or hashes of values, in results, logs, traces or metrics.
- **Bound connectors only.** A task names a connector that the control plane bound to this Gateway. Never accept a URL, namespace, credential or command from a task payload; refuse it.
- **No database or Redis driver.** The Gateway is stateless; durable state lives in the control plane.
- **No Agent dependency.** The Gateway never calls the Agent and the Agent never calls the Gateway.
- **Honest results.** Report what was observed and what couldn't be confirmed. ArgoCD `Healthy` alone is never proof that a secret change rolled out.

## Contributing

Feature branch off `main`, conventional commits, small PRs, CI green, then open a PR for maintainer review. Never push to `main`.

This repo is public. Keep account IDs, hostnames, cluster names, real secret paths and company names out of code, tests, commits, PRs and issues. Use placeholders such as `123456789012` and `argocd.example.com`.

**No AI attribution.** Commits and PRs describe the change, nothing else. Don't add `Co-Authored-By` trailers for AI assistants, "Generated with ..." lines or links to AI sessions to commit messages, PR titles or PR bodies. A squash merge copies the PR body into the commit on `main`, where it can't be edited later. If you use a coding assistant, turn off its commit and PR attribution in its settings.
