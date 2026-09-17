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

// swissMap mirrors internal/runtime/maps.Map (Go 1.24+ swissmap default).
// Keep in sync with internal/runtime/maps/map.go.
//
// 64-bit layout (size = 48 bytes):
//
//	used              uint64         offset  0
//	seed              uintptr        offset  8
//	dirPointer        unsafe.Pointer offset 16
//	dirLen            int            offset 24
//	globalDepth       uint8          offset 32
//	globalShift       uint8          offset 33
//	writing           uint8          offset 34
//	tombstonePossible bool           offset 35
//	(4 bytes implicit padding)
//	clearSeq          uint64         offset 40
type swissMap struct {
	used              uint64
	seed              uintptr
	dirPointer        unsafe.Pointer
	dirLen            int
	globalDepth       uint8
	globalShift       uint8
	writing           uint8
	tombstonePossible bool
	_                 [4]byte
	clearSeq          uint64
}

// swissTable mirrors internal/runtime/maps.table (Go 1.24+ swissmap).
// Keep in sync with internal/runtime/maps/table.go.
//
// 64-bit layout (size = 32 bytes):
//
//	used       uint16         offset  0
//	capacity   uint16         offset  2
//	growthLeft uint16         offset  4
//	localDepth uint8          offset  6
//	(1 byte implicit padding)
//	index      int            offset  8
//	groups     swissGroupsReference offset 16
type swissTable struct {
	used       uint16
	capacity   uint16
	growthLeft uint16
	localDepth uint8
	_pad       uint8
	index      int
	groups     swissGroupsReference
}

// swissGroupsReference mirrors internal/runtime/maps.groupsReference.
// Keep in sync with internal/runtime/maps/group.go.
type swissGroupsReference struct {
	data       unsafe.Pointer // *[lengthMask+1]group
	lengthMask uint64         // numGroups - 1 (numGroups is always a power of 2)
}

// getMapAllocatedSize estimates the number of bytes owned by the SwissTable map's
// internal structures. The caller is responsible for ensuring m is not
// concurrently mutated while this function runs.
//
// Group layout (conceptually, from internal/runtime/maps/group.go):
//
//	type group struct {
//	    ctrl  uint64               // 8 bytes: one control byte per slot
//	    slots [8]struct{ key K; elem V }
//	}
//
// SlotSize is modeled as sizeof(struct{ key K; elem V }) computed by the
// compiler using Go's usual struct layout rules. The actual runtime swissmap
// implementation may apply additional optimizations (for example, special-
// casing zero-sized values), so getMapAllocatedSize should be understood as
// an approximation/upper bound of the bytes owned by the map rather than an
// exact reflection of every internal optimization.
func getMapAllocatedSize[K comparable, V any](m map[K]V) int64 {
	if m == nil {
		return 0
	}

	sm := (*swissMap)(*(*unsafe.Pointer)(unsafe.Pointer(&m)))
	if sm == nil {
		return 0
	}

	type slot struct {
		key  K
		elem V
	}
	type group struct {
		slots [8]slot
		ctrl  uint64
	}

	groupSize := int64(unsafe.Sizeof(group{}))

	// swissMap struct itself, always allocated once the map is non-nil.
	size := int64(unsafe.Sizeof(*sm))

	if sm.dirLen == 0 {
		// Small-map optimisation: dirPointer points directly to one group.
		if sm.dirPointer != nil {
			size += groupSize
		}
		return size
	}

	// Large map: dirPointer is *[dirLen]*table.
	// Account for the directory pointer array itself.
	ptrSize := unsafe.Sizeof(uintptr(0))
	size += int64(sm.dirLen) * int64(ptrSize)

	// Deduplicate table pointers (directory entries may alias the same table).
	tables := make(map[unsafe.Pointer]struct{}, sm.dirLen)
	for i := 0; i < sm.dirLen; i++ {
		tp := *(*unsafe.Pointer)(unsafe.Pointer(uintptr(sm.dirPointer) + uintptr(i)*ptrSize))
		if tp != nil {
			tables[tp] = struct{}{}
		}
	}

	tableHdrSize := int64(unsafe.Sizeof(swissTable{}))
	for tp := range tables {
		t := (*swissTable)(tp)
		// swissTable struct itself.
		size += tableHdrSize
		// Groups backing array: (lengthMask+1) groups.
		numGroups := int64(t.groups.lengthMask + 1)
		size += numGroups * groupSize
	}

	return size
}
