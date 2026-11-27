# Cohosted canonical AI enrollment

This closes the existing OneSoul → SoulAuth seam under
SOUL-SOULAUTH-ALIGN-01 §§3.2–3.2.1. It does not create a Soul, change
Human permissions, issue a session, accept friendship, or grant model usage.

`SOULAUTH_CANONICAL_NODE_CONFIG` optionally names a root-owned, non-writable
JSON file. Without it there is no enrollment listener. The file specifies
`socket_path`, `peer_uid`, `soul_id`, and `source` (`node_ref`, `ai_actor_ref`,
`genesis_body_sha256`). All three source values and SoulId are exact scope,
not caller-selected authority. The operator must obtain them from the actual
Born original; the Node independently reopens and verifies the committed
OneSoul and current lifecycle before sending anything.

The socket parent is a dedicated directory owned by SoulAuth UID, with the
Node GID, mode 02750. Mount only this directory into the SourceAuth and Node
containers; do not share the broader Node control volume. The Node mount may
be read-only. Socket mode is 0660. Only the configured non-root kernel peer
UID is accepted, before reading a body. No TCP route exposes this writer.

The protocol is one JSON line, at most 16 KiB, per connection. It contains
`soul_id`, `source`, and the original reader's `verified_at_ms` (within 30 s).
SoulId is the verified OneSoul SoulId, never an Actor/Mind identifier with
its prefix stripped. The reply contains `status: verified`, the same
`soul_id`, `actor_identity_id`, and stable `subject_key`.

The sole writer atomically creates an AI ActorIdentity and the canonical
IdentityBinding. The provider is `soulseed`; provider_subject is SoulId;
binding_type is `canonical`; verification_state is `verified`. Provenance
lives in the binding's optional `canonical_source` object. The compatibility
ActorIdentity.canonical_actor_ref is not written. No HumanAccount or
Credential is created. Apply the additive canonical_source schema field
before enabling the listener; the application does not run DDL.

Exact retries return the same binding and subject. A revoked, conflicting,
noncanonical or non-AI binding is rejected without rewriting it. Missing or
lost replies are Unknown: reconcile by retrying the same request after
fresh OneSoul verification, never by generating another Soul or identity.

shortcut: This authenticates a cohosted Node by private mount capability
and kernel UID. A separate-host deployment requires its own reviewed,
authenticated transport; this socket contract must not be exposed over TCP.
