// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package webauthn

// WebAuthn log field and cache name strings.
const (
	LogFieldDiscoverable = "discoverable"
	cacheMDS3            = "mds3"
	cacheMDS3Generation  = "mds3_generation"
)

// maxMDS3BlobSize is the maximum accepted size of an MDS3 blob in bytes.
const maxMDS3BlobSize = 100 << 20

// Metadata cache policy strings.
const (
	CachePolicyStrict  = "strict"
	CachePolicyRelaxed = "relaxed"
)
