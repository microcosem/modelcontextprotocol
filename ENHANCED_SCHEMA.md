# Enhanced, Security-Focused MCP Schema (2025-08-09)

This document summarizes the security-focused enhancements added in `schema/2025-08-09/schema.ts`, how they improve MCP security, and how to adopt them.

## High-level changes

- First-class message security envelope via `_meta.security` on requests, notifications, and results
- Capability-based authorization with fine-grained scopes and short-lived, non-transferable tokens
- Message-level cryptography: identities (signatures), integrity hashes, replay protection, and optional encryption
- Security capability negotiation in `initialize`
- Dedicated security error codes (4900-4907)
- Capability issuance RPC: `security/issue`

## `_meta.security` envelope

Attach to each message under `params._meta.security` (and optionally on results/notifications):

- identity: `{ keyId, alg, jws, publicKey?, certificateChain? }`
  - Cryptographic sender authentication per message; supports PKI or key IDs
- capabilities: `(string | CapabilityToken)[]`
  - Least-privilege, time-boxed authorization per request (no ambient permissions)
- replay: `{ nonce, timestamp }`
  - Prevents replay within a bounded window; enables zero-trust
- integrity: `{ alg, hash, canonicalization? }`
  - Tamper detection on canonical payload; defense-in-depth if transport is compromised
- encryption: `{ alg, keyId?, iv?, aad?, ciphertext, tag? }`
  - Optional end-to-end confidentiality of `params` beyond TLS
- audit: `{ traceId?, requestId? }`
  - End-to-end traceability and incident response

### Example: signed + capability-bearing request

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "resources/read",
  "params": {
    "_meta": {
      "security": {
        "replay": { "nonce": "3XbV...", "timestamp": "2025-08-09T12:00:00Z" },
        "integrity": { "alg": "SHA-256", "hash": "base64-hash" },
        "capabilities": ["eyJhbGciOiJFZERTQSIs..."],
        "identity": {
          "keyId": "kid:client",
          "alg": "EdDSA",
          "jws": "<detached-jws>"
        },
        "audit": { "traceId": "trace-123", "requestId": "req-abc" }
      }
    },
    "uri": "file:///project/README.md"
  }
}
```

### Example: encrypted parameters

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "method": "resources/read",
  "params": {
    "_meta": {
      "security": {
        "replay": { "nonce": "v2t4...", "timestamp": "2025-08-09T12:02:00Z" },
        "encryption": {
          "alg": "A256GCM",
          "keyId": "kid:server",
          "iv": "Q2hhbmdlbWU=",
          "aad": "eyJqd3QiOnRydWV9",
          "ciphertext": "X1c+...",
          "tag": "bG9naW4="
        }
      }
    }
  }
}
```

## Capability model

- CapabilityToken: either a compact `token` (JWT, PASETO, CWT) or a structured `claims` object
- CapabilityClaims:
  - scope: array of fine-grained entries
    - resource: `{ type: "resource", actions: ["read"|"subscribe"|"unsubscribe"|"list"|"templates_list"], uri?, uriTemplate? }`
    - tool: `{ type: "tool", actions: ["call"|"list"], name?, namePattern? }`
    - prompt: `{ type: "prompt", actions: ["get"|"list"], name?, namePattern? }`
  - constraints: `{ notBefore?, expiresAt?, audience?, issuer?, subject?, context? }`
  - nonTransferable: boolean (binds token to presenter)

### Issuance RPC: `security/issue`

Servers validate identity proof and policy, then issue scoped, short-lived capabilities.

Request:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "security/issue",
  "params": {
    "requested": [
      {
        "scope": [
          {
            "type": "resource",
            "actions": ["read"],
            "uriTemplate": "file://*/README.md"
          }
        ],
        "constraints": { "expiresAt": "2025-08-09T12:05:00Z" },
        "nonTransferable": true
      }
    ],
    "proof": { "keyId": "kid:client", "alg": "EdDSA", "jws": "<detached-jws>" },
    "audience": "urn:mcp:server"
  }
}
```

Response (example):

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "capabilities": ["eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...."],
    "expiresAt": "2025-08-09T12:05:00Z"
  }
}
```

## Security capability negotiation (initialize)

- `ClientCapabilities.security` / `ServerCapabilities.security`:
  - `requireSignedRequests`, `requireSignedResponses`, `requireCapabilities`
  - `supportedSignatureAlgs`, `supportedEncryptionAlgs`
  - `acceptCapabilityFormats` ("jwt", "paseto", "cwt", "object")
  - `maxReplayWindowSeconds`

Benefit: progressive rollout and explicit policy expectations before enforcement.

## Security error codes

- 4900 UNAUTHORIZED: missing or invalid identity/capabilities
- 4901 FORBIDDEN: capability present but not sufficient for this action
- 4902 REPLAY_DETECTED: nonce/timestamp outside window or reused
- 4903 INVALID_SIGNATURE: signature or integrity failure
- 4904 INVALID_CAPABILITY: malformed token/claims
- 4905 EXPIRED_CAPABILITY: token expired or not yet valid
- 4906 ENCRYPTION_REQUIRED: policy requires encryption but absent
- 4907 DECRYPTION_FAILED: could not decrypt (e.g., wrong key)

## Why this improves security

- Authentication-first: message-level identity proof supports mutual auth and key rotation
- Stateless by default: each message stands alone with its own authZ/authN; no session hijacking
- Least privilege: capabilities scope precisely to resources/tools/prompts with tight lifetimes
- Zero-trust: do not rely on "trusted networks"; validate per-message invariants
- Defense-in-depth: integrity and optional encryption protect even if transport is compromised
- Auditability: `traceId`/`requestId` enable robust forensics and correlation
- Verifiability: small, explicit invariants lend themselves to formal checks

## Recommended rollout (progressive hardening)

1. Negotiate: advertise `security` capabilities during `initialize`
2. Start verifying: enforce `replay` and `integrity` (log failures), continue to allow requests
3. Introduce capabilities: require tokens for privileged methods; soft-fail on missing signatures
4. Require signatures: enforce identity on all requests/responses
5. Encrypt sensitive: require message-level `encryption` for sensitive methods/parameters

## Validation checklist (server side)

- Replay: `timestamp` within `maxReplayWindowSeconds`, `nonce` unique per keyId
- Integrity: recompute canonical payload hash; return 4903 on mismatch
- Identity: verify `identity.jws` and `keyId`/PKI; apply revocation/rotation policy
- Capabilities: validate scope/constraints; return 4901 (or 4905/4904) as appropriate
- Encryption: if required, enforce presence and decrypt; return 4906/4907 on violations
- Audit: propagate and log `traceId`/`requestId`

---

See also:

- Schema: `schema/2025-08-09/schema.ts`
- Generated docs: `docs/specification/2025-08-09/schema.mdx`
- Migration guide: `docs/specification/2025-08-09/migration.mdx`
- Examples: `docs/specification/2025-08-09/examples.mdx`
