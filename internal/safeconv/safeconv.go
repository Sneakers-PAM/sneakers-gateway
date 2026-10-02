// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package safeconv provides audited, overflow-safe narrowing of wide integers
// into fixed-width protobuf scalar types. A raw int32(...) at a call site trips
// the gosec G115 (CWE-190) gate; centralizing one clamped, //nosec-justified
// conversion keeps services consistent.
package safeconv

import "math"

// Int32 clamps n into the int32 range.
func Int32(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n) // #nosec G115 -- bounds-checked immediately above
}

// Uint32 clamps n into the uint32 range.
func Uint32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n) // #nosec G115 -- bounds-checked immediately above
}

// IntFromUint64 clamps u into the non-negative int range.
func IntFromUint64(u uint64) int {
	if u > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(u) // #nosec G115 -- bounds-checked immediately above
}

// IntFromInt64 clamps n into the int range (a no-op on 64-bit build targets,
// but keeps the conversion audited/lint-clean on any platform where int is
// narrower than int64 — e.g. the identity ServiceAccount/ApiToken Unix
// timestamp fields, which are int64 on the wire but graphql.Int (Go int) in
// the GraphQL schema).
func IntFromInt64(n int64) int {
	if n < math.MinInt {
		return math.MinInt
	}
	if n > math.MaxInt {
		return math.MaxInt
	}
	return int(n) // #nosec G115 -- bounds-checked immediately above
}
