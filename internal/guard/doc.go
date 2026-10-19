// Package guard holds repository guard tests that CI runs with the rest
// of the test suite. They check the module graph and the source tree
// for things the Gateway must never contain: a database, Redis or KV
// driver, k8s.io/client-go, a Secrets Bridge platform module (api,
// worker, agent, controller), an http.Transport or default client
// outside internal/readonly and internal/client, and a Kubernetes
// Secrets path in non-test code. The package has no non-test code.
package guard
