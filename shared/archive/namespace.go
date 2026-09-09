//go:build linux

package archive

import (
	"cmp"
	"fmt"
	"slices"
	"syscall"
)

// UnpackNamespace is the complete on-disk mapping for a 65536-ID container.
// Both maps must exclude host root. It is not an identity allocator: callers
// must reserve the host IDs and persist this mapping with the root generation.
type UnpackNamespace struct {
	UID []syscall.SysProcIDMap
	GID []syscall.SysProcIDMap
}

// Validate rejects incomplete, overlapping or privileged extraction mappings.
func (n UnpackNamespace) Validate() error {
	for _, group := range []struct {
		name    string
		entries []syscall.SysProcIDMap
	}{{"UID", n.UID}, {"GID", n.GID}} {
		if len(group.entries) == 0 || len(group.entries) > 340 {
			return fmt.Errorf("Invalid unpack %s map length", group.name)
		}
		entries := slices.Clone(group.entries)
		slices.SortFunc(entries, func(a, b syscall.SysProcIDMap) int {
			return cmp.Compare(a.ContainerID, b.ContainerID)
		})
		next := int64(0)
		for _, entry := range entries {
			if int64(entry.ContainerID) != next || entry.Size <= 0 || entry.Size > 65536 || entry.HostID <= 0 || int64(entry.HostID) > 4294967294-int64(entry.Size)+1 {
				return fmt.Errorf("Invalid unpack %s map extent", group.name)
			}
			next += int64(entry.Size)
			if next > 65536 {
				return fmt.Errorf("Unpack %s map exceeds container ID space", group.name)
			}
		}
		if next != 65536 {
			return fmt.Errorf("Incomplete unpack %s map", group.name)
		}
		slices.SortFunc(entries, func(a, b syscall.SysProcIDMap) int {
			return cmp.Compare(a.HostID, b.HostID)
		})
		for i := 1; i < len(entries); i++ {
			if int64(entries[i].HostID) < int64(entries[i-1].HostID)+int64(entries[i-1].Size) {
				return fmt.Errorf("Overlapping unpack %s host IDs", group.name)
			}
		}
	}
	return nil
}
