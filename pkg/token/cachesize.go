// Copyright 2023 LY Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token

import "unsafe"

// https://github.com/golang/go/blob/go1.24.0/src/internal/runtime/maps/map.go
type swissMap struct {
	used              uint64
	seed              uintptr
	dirPtr            unsafe.Pointer
	dirLen            int
	globalDepth       uint8
	globalShift       uint8
	writing           uint8
	tombstonePossible bool
	clearSeq          uint64
}

// https://github.com/golang/go/blob/go1.24.0/src/internal/runtime/maps/table.go
type swissTable struct {
	used       uint16
	capacity   uint16
	growthLeft  uint16
	localDepth uint8
	index      int
	groups     swissGroupsReference
}

// https://github.com/golang/go/blob/go1.24.0/src/internal/runtime/maps/group.go
type swissGroupsReference struct {
	data       unsafe.Pointer
	lengthMask uint64
}

// emptyInterface is the internally representation of interface{}.
type emptyInterface struct {
	_type unsafe.Pointer
	value unsafe.Pointer
}

// extractSwissMap extracts the underlying swissMap struct pointer from a map unsafely.
func extractSwissMap(m interface{}) *swissMap {
	ei := (*emptyInterface)(unsafe.Pointer(&m))
	return (*swissMap)(ei.value)
}

// getMapAllocatedSize returns the estimated memory allocated by the map's internal data structures.
func getMapAllocatedSize(c map[CacheKey]Token) int64 {
	sm := extractSwissMap(c)

	slotSize := int64(unsafe.Sizeof(CacheKey{})) + 16 // 16 = interface size (type ptr + data ptr)
	groupDataSize := int64(8) + int64(8)*slotSize     // 8 ctrl bytes + 8 slots per group

	if sm.dirLen == 0 {
		if sm.dirPtr == nil {
			return 0
		}
		// Small map: dirPtr points directly to a single group
		return groupDataSize
	}

	// Large map: dirPtr points to [dirLen]*table
	dirSize := int64(sm.dirLen) * int64(unsafe.Sizeof(uintptr(0)))

	dir := unsafe.Slice((*unsafe.Pointer)(sm.dirPtr), sm.dirLen)
	seen := make(map[unsafe.Pointer]bool)
	var totalTableSize int64
	for _, entry := range dir {
		if entry == nil || seen[entry] {
			continue
		}
		seen[entry] = true
		tab := (*swissTable)(entry)
		numGroups := int64(tab.groups.lengthMask + 1)
		totalTableSize += int64(unsafe.Sizeof(swissTable{})) + numGroups*groupDataSize
	}

	return dirSize + totalTableSize
}
