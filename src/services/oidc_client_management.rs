use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};

use crate::{
    models::{
        oidc_client::{
            CreateOidcClientRequest, GrantType, OidcClient, OidcClientResponse, ResponseType,
        },
        subject::{Subject, SubjectType},
    },
    services::database::Database,
};

#[derive(Clone)]
pub struct OidcClientService {
    db: Arc<Database>,
}

impl OidcClientService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn create_client(
        &self,
        request: CreateOidcClientRequest,
        created_by: &str,
    ) -> Result<OidcClientResponse> {
        let client_id = generate_client_id();
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret);
        let now = Utc::now().timestamp();

        let allowed_scopes = request.allowed_scopes.unwrap_or_else(|| {
            vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
        });
        let allowed_grant_types = request.allowed_grant_types.unwrap_or_else(|| {
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        });
        let allowed_response_types = request
            .allowed_response_types
            .unwrap_or_else(|| vec![ResponseType::Code]);

        let subject_id = if allowed_grant_types.contains(&GrantType::ClientCredentials) {
            Some(self.create_agent_subject().await?)
        } else {
            None
        };

        let client = OidcClient {
            id: None,
            client_id: client_id.clone(),
            subject_id: subject_id.clone(),
            client_secret_hash,
            client_name: request.client_name.clone(),
            client_type: request.client_type.clone(),
            redirect_uris: request.redirect_uris.clone(),
            post_logout_redirect_uris: request.post_logout_redirect_uris.unwrap_or_default(),
            allowed_scopes: allowed_scopes.clone(),
            allowed_grant_types: allowed_grant_types.clone(),
            allowed_response_types: allowed_response_types.clone(),
            require_pkce: request.require_pkce.unwrap_or(true),
            access_token_lifetime: request.access_token_lifetime.unwrap_or(3600),
            refresh_token_lifetime: request.refresh_token_lifetime.unwrap_or(86400),
            id_token_lifetime: request.id_token_lifetime.unwrap_or(3600),
            is_active: true,
            created_by: created_by.to_string(),
            created_at: now,
            updated_at: now,
        };

        self.save_client(&client).await?;

        Ok(to_client_response(client, client_secret))
    }

    pub async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        let query = "SELECT * FROM oidc_client WHERE client_id = $client_id AND is_active = true LIMIT 1";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("client_id", client_id.to_owned()))
            .await?;

        let clients: Vec<OidcClient> = result.take(0)?;
        clients
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Client not found"))
    }

    pub async fn list_clients(
        &self,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<OidcClientResponse>> {
        let limit = limit.unwrap_or(50);
        let offset = offset.unwrap_or(0);

        let query = "SELECT * FROM oidc_client WHERE is_active = true ORDER BY created_at DESC LIMIT $limit START $offset";

        let mut result = self
            .db
            .client
            .query(query)
            .bind(("limit", limit))
            .bind(("offset", offset))
            .await?;

        let clients: Vec<OidcClient> = result.take(0)?;

        Ok(clients
            .into_iter()
            .map(|client| to_client_response(client, "***".to_string()))
            .collect())
    }

    pub async fn update_client(
        &self,
        client_id: &str,
        request: CreateOidcClientRequest,
    ) -> Result<OidcClientResponse> {
        let mut client = self.get_client(client_id).await?;

        let grant_types = request
            .allowed_grant_types
            .unwrap_or_else(|| client.allowed_grant_types.clone());
        if grant_types.contains(&GrantType::ClientCredentials) && client.subject_id.is_none() {
            client.subject_id = Some(self.create_agent_subject().await?);
        }

        client.client_name = request.client_name;
        client.client_type = request.client_type;
        client.redirect_uris = request.redirect_uris;
        client.post_logout_redirect_uris = request.post_logout_redirect_uris.unwrap_or_default();
        client.allowed_scopes = request.allowed_scopes.unwrap_or(client.allowed_scopes);
        client.allowed_grant_types = grant_types;
        client.allowed_response_types = request
            .allowed_response_types
            .unwrap_or(client.allowed_response_types);
        client.require_pkce = request.require_pkce.unwrap_or(client.require_pkce);
        client.access_token_lifetime = request
            .access_token_lifetime
            .unwrap_or(client.access_token_lifetime);
        client.refresh_token_lifetime = request
            .refresh_token_lifetime
            .unwrap_or(client.refresh_token_lifetime);
        client.id_token_lifetime = request.id_token_lifetime.unwrap_or(client.id_token_lifetime);
        client.updated_at = Utc::now().timestamp();

        self.update_client_in_db(&client).await?;

        Ok(to_client_response(client, "***".to_string()))
    }

    pub async fn disable_client(&self, client_id: &str) -> Result<()> {
        let query = "UPDATE oidc_client SET is_active = false, updated_at = time::now() WHERE client_id = $client_id";

        self.db
            .client
            .query(query)
            .bind(("client_id", client_id.to_owned()))
            .await?;

        Ok(())
    }

    pub async fn regenerate_client_secret(&self, client_id: &str) -> Result<String> {
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret);

        let query =
            "UPDATE oidc_client SET client_secret_hash = $hash, updated_at = time::now() WHERE client_id = $client_id";

        self.db
            .client
            .query(query)
            .bind(("hash", client_secret_hash))
            .bind(("client_id", client_id.to_owned()))
            .await?;

        Ok(client_secret)
    }

    pub async fn verify_client_secret(&self, client_id: &str, client_secret: &str) -> Result<bool> {
        let client = self.get_client(client_id).await?;
        let provided_hash = hash_client_secret(client_secret);
        Ok(provided_hash == client.client_secret_hash)
    }

    async fn create_agent_subject(&self) -> Result<String> {
        let now = Utc::now().timestamp();
        let subject = Subject {
            id: None,
            subject_type: SubjectType::Agent.as_str().to_string(),
            created_at: now,
            updated_at: now,
        };

        let created: Subject = self.db.create_record("subject", &subject).await?;
        let created_id = created
            .id
            .ok_or_else(|| anyhow!("Created subject missing id"))?;
        Ok(crate::utils::record_id::record_id_key_to_string(&created_id))
    }

    async fn save_client(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            CREATE oidc_client CONTENT {
                client_id: $client_id,
                subject_id: $subject_id,
                client_secret_hash: $client_secret_hash,
                client_name: $client_name,
                client_type: $client_type,
                redirect_uris: $redirect_uris,
                post_logout_redirect_uris: $post_logout_redirect_uris,
                allowed_scopes: $allowed_scopes,
                allowed_grant_types: $allowed_grant_types,
                allowed_response_types: $allowed_response_types,
                require_pkce: $require_pkce,
                access_token_lifetime: $access_token_lifetime,
                refresh_token_lifetime: $refresh_token_lifetime,
                id_token_lifetime: $id_token_lifetime,
                is_active: $is_active,
                created_by: $created_by,
                created_at: $created_at,
                updated_at: $updated_at
            }
        "#;

        self.db
            .client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("subject_id", client.subject_id.clone().map(|id| format!("subject:{id}"))))
            .bind(("client_secret_hash", client.client_secret_hash.clone()))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client.client_type.clone()))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind(("post_logout_redirect_uris", client.post_logout_redirect_uris.clone()))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind(("allowed_grant_types", client.allowed_grant_types.clone()))
            .bind(("allowed_response_types", client.allowed_response_types.clone()))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("is_active", client.is_active))
            .bind(("created_by", client.created_by.clone()))
            .bind(("created_at", client.created_at))
            .bind(("updated_at", client.updated_at))
            .await?;

        Ok(())
    }

    async fn update_client_in_db(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            UPDATE oidc_client SET
                subject_id = $subject_id,
                client_name = $client_name,
                client_type = $client_type,
                redirect_uris = $redirect_uris,
                post_logout_redirect_uris = $post_logout_redirect_uris,
                allowed_scopes = $allowed_scopes,
                allowed_grant_types = $allowed_grant_types,
                allowed_response_types = $allowed_response_types,
                require_pkce = $require_pkce,
                access_token_lifetime = $access_token_lifetime,
                refresh_token_lifetime = $refresh_token_lifetime,
                id_token_lifetime = $id_token_lifetime,
                updated_at = $updated_at
            WHERE client_id = $client_id
        "#;

        self.db
            .client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("subject_id", client.subject_id.clone().map(|id| format!("subject:{id}"))))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client.client_type.clone()))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind(("post_logout_redirect_uris", client.post_logout_redirect_uris.clone()))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind(("allowed_grant_types", client.allowed_grant_types.clone()))
            .bind(("allowed_response_types", client.allowed_response_types.clone()))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("updated_at", client.updated_at))
            .await?;

        Ok(())
    }
}

fn to_client_response(client: OidcClient, client_secret: String) -> OidcClientResponse {
    OidcClientResponse {
        client_id: client.client_id,
        subject_id: client.subject_id,
        client_secret,
        client_name: client.client_name,
        client_type: client.client_type,
        redirect_uris: client.redirect_uris,
        post_logout_redirect_uris: client.post_logout_redirect_uris,
        allowed_scopes: client.allowed_scopes,
        allowed_grant_types: client.allowed_grant_types,
        allowed_response_types: client.allowed_response_types,
        require_pkce: client.require_pkce,
        access_token_lifetime: client.access_token_lifetime,
        refresh_token_lifetime: client.refresh_token_lifetime,
        id_token_lifetime: client.id_token_lifetime,
        is_active: client.is_active,
        created_at: client.created_at,
        updated_at: client.updated_at,
    }
}

fn generate_client_id() -> String {
    let timestamp = Utc::now().timestamp_millis();
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("client_{}{random}", timestamp)
}

fn generate_client_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn hash_client_secret(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}
