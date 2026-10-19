package loop

import (
	"crypto/rand"
	"fmt"
)

// NewReplicaID returns a random UUIDv4 for this process. It is not
// derived from the pod name or UID, so no cluster naming reaches the
// control plane. It is informational; attempt_id is the fence.
func NewReplicaID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("loop: replica id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
