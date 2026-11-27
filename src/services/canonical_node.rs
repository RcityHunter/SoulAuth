//! Cohosted Node ingress. No public route, human role, or self-declared SoulId
//! can mint a canonical binding. The configured Node must verify OneSoul first.
use crate::{
    error::{AuthError, Result},
    models::{
        actor_identity::{ActorIdentity, ActorKind},
        identity_binding::{CanonicalSource, IdentityBinding},
    },
    services::database::Database,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::watch,
    time::{timeout, Duration},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    socket_path: String,
    peer_uid: u32,
    soul_id: String,
    source: CanonicalSource,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    soul_id: String,
    source: CanonicalSource,
    verified_at_ms: i64,
}

#[derive(Serialize)]
struct Reply {
    status: &'static str,
    soul_id: String,
    actor_identity_id: String,
    subject_key: String,
}

pub struct CanonicalNodeIngress {
    listener: UnixListener,
    config: Config,
}
impl CanonicalNodeIngress {
    pub fn configured() -> anyhow::Result<Option<Self>> {
        let path = match std::env::var("SOULAUTH_CANONICAL_NODE_CONFIG") {
            Ok(path) => path,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let metadata = std::fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "canonical Node config must be a root-owned non-writable regular file"
        );
        let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
        anyhow::ensure!(
            config.peer_uid != 0
                && !config.soul_id.trim().is_empty()
                && !config.source.node_ref.trim().is_empty()
                && !config.source.ai_actor_ref.trim().is_empty()
                && config.source.genesis_body_sha256.len() == 64
                && config
                    .source
                    .genesis_body_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "invalid bounded canonical Node scope"
        );
        let path = Path::new(&config.socket_path);
        anyhow::ensure!(path.is_absolute(), "canonical Node socket must be absolute");
        let parent = std::fs::symlink_metadata(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("missing socket parent"))?,
        )?;
        anyhow::ensure!(
            parent.is_dir() && parent.mode() & 0o022 == 0,
            "canonical Node socket directory must not be group/world writable"
        );
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.file_type().is_socket() && meta.uid() == parent.uid(),
                    "refusing to replace non-owned socket"
                );
                // A live peer is never unlinked. A stale socket is safe in this private directory.
                anyhow::ensure!(
                    std::os::unix::net::UnixStream::connect(path).is_err(),
                    "canonical Node socket already active"
                );
                std::fs::remove_file(path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(Some(Self { listener, config }))
    }

    pub async fn run(
        self,
        db: Arc<Database>,
        mut stop: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        loop {
            let (stream, _) = tokio::select! {
                _ = stop.changed() => return Ok(()),
                result = self.listener.accept() => result?,
            };
            // Check kernel credentials before reading any caller-controlled bytes.
            if stream.peer_cred()?.uid() != self.config.peer_uid {
                continue;
            }
            let _ = timeout(Duration::from_secs(10), self.handle(stream, &db)).await;
        }
    }

    async fn handle(&self, stream: UnixStream, db: &Database) -> anyhow::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut frame = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            anyhow::ensure!(!available.is_empty(), "incomplete canonical request");
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |i| i + 1);
            anyhow::ensure!(frame.len() + count <= 16_384, "canonical request too large");
            let done = available[count - 1] == b'\n';
            frame.extend_from_slice(&available[..count]);
            reader.consume(count);
            if done {
                break;
            }
        }
        let request: Request = serde_json::from_slice(&frame)?;
        validate(
            &self.config,
            &request,
            chrono::Utc::now().timestamp_millis(),
        )?;
        // Lost acknowledgements are Unknown, never a new identity: same SoulId
        // deterministically reaches the same atomic create and readback.
        let reply = register(db, &request).await?;
        let mut bytes = serde_json::to_vec(&reply)?;
        bytes.push(b'\n');
        reader.get_mut().write_all(&bytes).await?;
        reader.get_mut().shutdown().await?;
        Ok(())
    }
}

fn validate(config: &Config, request: &Request, now: i64) -> Result<()> {
    if request.soul_id != config.soul_id
        || request.source != config.source
        || now.abs_diff(request.verified_at_ms) > 30_000
    {
        return Err(AuthError::PermissionDenied);
    }
    Ok(())
}

async fn register(db: &Database, request: &Request) -> Result<Reply> {
    let key = format!("canonical-{:x}", Sha256::digest(request.soul_id.as_bytes()));
    let subject = uuid::Uuid::new_v4().to_string();
    db.raw_query(
        "canonical_node_register",
        r#"
        BEGIN TRANSACTION;
        LET $existing = SELECT * FROM identity_binding
            WHERE provider = 'soulseed' AND provider_subject = $soul_id;
        IF array::len($existing) = 0 {
            CREATE type::record('actor_identity', $key) CONTENT {
                subject_key: $subject, actor_kind: 'ai_actor', identity_source: 'soulseed',
                status: 'active', created_at: $now, updated_at: $now
            };
            CREATE type::record('identity_binding', $key) CONTENT {
                actor_identity_id: type::record('actor_identity', $key),
                provider: 'soulseed', provider_subject: $soul_id, binding_type: 'canonical',
                verification_state: 'verified', bound_at: $now, canonical_source: $source
            };
        };
        COMMIT TRANSACTION;
    "#,
        serde_json::json!({"key":key,"subject":subject,"soul_id":request.soul_id,
        "source":request.source,"now":chrono::Utc::now().timestamp()}),
    )
    .await?;
    let bindings: Vec<IdentityBinding> = db.query_take0_vec("canonical_node_readback",
        "SELECT * FROM identity_binding WHERE provider = 'soulseed' AND provider_subject = $soul_id",
        serde_json::json!({"soul_id":request.soul_id})).await?;
    let binding = bindings
        .first()
        .filter(|binding| {
            bindings.len() == 1
                && binding.is_active()
                && binding.canonical_source.as_ref() == Some(&request.source)
        })
        .ok_or(AuthError::PermissionDenied)?;
    let actor: ActorIdentity = db
        .find_record_by_field(
            "actor_identity",
            "id",
            &format!(
                "actor_identity:{}",
                crate::utils::record_id::record_id_key_to_string(&binding.actor_identity_id)
            ),
        )
        .await?
        .ok_or(AuthError::PermissionDenied)?;
    if actor.actor_kind != ActorKind::AiActor.as_str() || !actor.can_authenticate() {
        return Err(AuthError::PermissionDenied);
    }
    Ok(Reply {
        status: "verified",
        soul_id: request.soul_id.clone(),
        actor_identity_id: format!(
            "actor_identity:{}",
            crate::utils::record_id::record_id_key_to_string(&binding.actor_identity_id)
        ),
        subject_key: actor.subject_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_source_must_match_the_bounded_node_and_fresh_verified_soul() {
        let c = Config {
            socket_path: "/private/node.sock".into(),
            peer_uid: 10002,
            soul_id: "soul-real".into(),
            source: CanonicalSource {
                node_ref: "node-real".into(),
                ai_actor_ref: "actor-real".into(),
                genesis_body_sha256: "a".repeat(64),
            },
        };
        let mut r = Request {
            soul_id: c.soul_id.clone(),
            source: c.source.clone(),
            verified_at_ms: 100_000,
        };
        assert!(validate(&c, &r, 100_000).is_ok());
        assert!(validate(&c, &r, 130_001).is_err());
        r.soul_id = "actor-real".into();
        assert!(validate(&c, &r, 100_000).is_err());
        r.soul_id = c.soul_id.clone();
        r.source.ai_actor_ref = "other-actor".into();
        assert!(validate(&c, &r, 100_000).is_err());
        r.source = c.source.clone();
        r.source.node_ref = "other-node".into();
        assert!(validate(&c, &r, 100_000).is_err());
        r.source = c.source.clone();
        r.source.genesis_body_sha256 = "b".repeat(64);
        assert!(validate(&c, &r, 100_000).is_err());
    }
}
