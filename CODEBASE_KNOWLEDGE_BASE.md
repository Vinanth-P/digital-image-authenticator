# Current architecture reference

The previous v2 reference described guarantees that the implementation did not establish. README.md is the current operational and trust-boundary reference; EVALUATION.md defines the validation protocol.

## Evidence lifecycle

1. Access-control middleware authenticates the single operator (or restricts local mode to loopback). Host/origin checks and request-size limits apply to HTTP and WebSockets.
2. Ingestion validates actual image encoding, pixel count, frame count, and size; it saves original bytes separately and computes experimental forensic signals off the event loop.
3. The record and an `analysis` audit event are committed together. Audit snapshots include image hash, scores, registered signer, signature, provenance status and timestamp metadata.
4. Server signing checks key credentials and record/file integrity before creating a derivative. It embeds an unverified PNG analysis note where supported, signs final bytes, checks that signature, and commits the `server_signing` event. Failure removes the new derivative and preserves the original.
5. Browser signing registers the actual public key and stores a non-exportable private CryptoKey in IndexedDB. A detached signature is verified against the stored bytes; the server never changes those bytes afterward.
6. Verification recomputes retained event hashes and the Merkle root, verifies the signed checkpoint against the local key, and compares the current record with its latest snapshot. Signature verification is independent.
7. Deletion appends a tombstone, retains historical events/checkpoints, and removes the current record and associated source/result files. Original image IDs are not reused.

## Cryptographic and operational limits

Leaf hashing is SHA-256(0x00 || canonical JSON). Internal nodes use SHA-256(0x01 || left digest bytes || right digest bytes). Trees split at the largest power of two less than the leaf count. Checkpoints sign version, root, size and UTC creation time using Ed25519. The local private key is encrypted using the installation secret.

This is a local integrity log, not a complete RFC 6962 transparency service. There are no public consistency-proof/monitoring services. An attacker controlling the host and signing secrets can rewrite history. External checkpoint retention is needed for rollback detection. Tree rebuilds and record checks are O(N).

The workbench supports one trusted operator and one application worker. There are no per-user ownership boundaries. Public verification URLs are protected by the same access policy as the rest of the application.

## Compatibility

Existing routes and main DOM IDs are retained. Security restrictions intentionally tighten request behavior: strong passphrases for new server keys, actual public keys for browser registration, no plaintext key export, input rejection, authentication for hosted access, and explicit legacy imports.

Legacy score/probability/verdict field names remain transport-compatible but represent experimental signals. The C2PA-shaped stored analysis note is explicitly unverified; it is not a Content Credential. Predicted origin is stored as `predicted_source_type`, never an authoritative `digitalSourceType` claim. Local receipts are not RFC 3161 tokens.

## Engineering checks

Run `python -m pytest` with dependencies from requirements-dev.txt. Fixtures isolate all mutable runtime data. Keep failure-atomicity, key identity, record tampering, checkpoint validation, access control and browser behavior tests when modifying these flows. Do not restore hardcoded report PASS labels or use generated fixtures to claim external accuracy.
