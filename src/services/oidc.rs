use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    models::{
        oidc_client::{ClientType, GrantType, OidcClient, ResponseType},
        oidc_token::{
            AccessTokenClaims, AuthorizeRequest, IdTokenClaims, OidcAccessToken,
            OidcAuthorizationCode, OidcRefreshToken, TokenRequest, TokenResponse,
            TokenSubjectInfoResponse, UserInfoResponse,
        },
        subject::SubjectType,
        user::User,
    },
    services::database::Database,
};

#[derive(Clone)]
pub struct OidcService {
    db: Arc<Database>,
    config: Config,
    signing_key: EncodingKey,
    verification_key: DecodingKey,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl OidcService {
    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        let signing_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let verification_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Ok(Self {
            db,
            config,
            signing_key,
            verification_key,
        })
    }

    pub fn get_configuration(&self) -> OidcConfiguration {
        let base_url = &self.config.app_url;

        OidcConfiguration {
            issuer: base_url.clone(),
            authorization_endpoint: format!("{}/api/oidc/authorize", base_url),
            token_endpoint: format!("{}/api/oidc/token", base_url),
            userinfo_endpoint: format!("{}/api/oidc/userinfo", base_url),
            jwks_uri: format!("{}/api/oidc/jwks", base_url),
            end_session_endpoint: format!("{}/api/oidc/logout", base_url),
            response_types_supported: vec!["code".to_string(), "id_token".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["HS256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
        }
    }

    pub async fn create_authorization_code(
        &self,
        request: &AuthorizeRequest,
        user_id: &str,
    ) -> Result<String> {
        let client = self.get_client(&request.client_id).await?;
        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(anyhow!("Invalid redirect URI"));
        }

        let response_types: Vec<ResponseType> = request
            .response_type
            .split_whitespace()
            .map(|rt| match rt {
                "code" => Ok(ResponseType::Code),
                "id_token" => Ok(ResponseType::IdToken),
                _ => Err(anyhow!("Unsupported response type")),
            })
            .collect::<Result<Vec<_>>>()?;

        for rt in &response_types {
            if !client.allowed_response_types.contains(rt) {
                return Err(anyhow!("Response type not allowed for this client"));
            }
        }

        if client.require_pkce && request.code_challenge.is_none() {
            return Err(anyhow!("PKCE is required for this client"));
        }

        let code = generate_random_string(32);
        let expires_at = Utc::now().timestamp() + 600;
        let scope = request.scope.clone().unwrap_or_else(|| "openid".to_string());

        let auth_code = OidcAuthorizationCode {
            id: None,
            code: code.clone(),
            client_id: request.client_id.clone(),
            user_id: user_id.to_string(),
            redirect_uri: request.redirect_uri.clone(),
            scope,
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            used: false,
            expires_at,
            created_at: Utc::now().timestamp(),
        };

        self.save_authorization_code(&auth_code).await?;
        Ok(code)
    }

    pub async fn exchange_code_for_tokens(&self, request: &TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            "client_credentials" => self.handle_client_credentials_grant(request).await,
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    async fn handle_authorization_code_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let code = request
            .code
            .as_ref()
            .ok_or_else(|| anyhow!("Missing authorization code"))?;
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| anyhow!("Missing redirect URI"))?;

        let client = self.get_client(&request.client_id).await?;
        self.validate_client_credentials(&client, request.client_secret.as_deref())?;

        let mut auth_code = self.get_authorization_code(code).await?;
        if auth_code.used {
            return Err(anyhow!("Authorization code already used"));
        }
        if auth_code.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Authorization code expired"));
        }
        if auth_code.client_id != request.client_id {
            return Err(anyhow!("Authorization code was not issued to this client"));
        }
        if auth_code.redirect_uri != *redirect_uri {
            return Err(anyhow!("Redirect URI mismatch"));
        }

        if let Some(code_challenge) = &auth_code.code_challenge {
            let code_verifier = request
                .code_verifier
                .as_ref()
                .ok_or_else(|| anyhow!("Code verifier required"))?;

            if !self.verify_pkce(code_challenge, &auth_code.code_challenge_method, code_verifier)? {
                return Err(anyhow!("Invalid code verifier"));
            }
        }

        auth_code.used = true;
        self.update_authorization_code(&auth_code).await?;

        let user = self.get_user_by_id(&auth_code.user_id).await?;
        let subject_id = user
            .subject_id
            .as_ref()
            .map(crate::utils::record_id::record_id_key_to_string)
            .ok_or_else(|| anyhow!("User subject_id is missing"))?;

        self.generate_tokens(
            &client,
            &subject_id,
            SubjectType::Human,
            Some(&auth_code.user_id),
            &auth_code.scope,
            auth_code.nonce.as_deref(),
        )
        .await
    }

    async fn handle_refresh_token_grant(&self, request: &TokenRequest) -> Result<TokenResponse> {
        let refresh_token = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow!("Missing refresh token"))?;

        let mut stored_refresh_token = self.get_refresh_token(refresh_token).await?;
        if stored_refresh_token.used {
            return Err(anyhow!("Refresh token already used"));
        }
        if stored_refresh_token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Refresh token expired"));
        }
        if stored_refresh_token.client_id != request.client_id {
            return Err(anyhow!("Refresh token was not issued to this client"));
        }

        let client = self.get_client(&request.client_id).await?;
        self.validate_client_credentials(&client, request.client_secret.as_deref())?;

        stored_refresh_token.used = true;
        self.update_refresh_token(&stored_refresh_token).await?;
        self.revoke_access_token(&stored_refresh_token.access_token).await?;

        let scope = request.scope.as_deref().unwrap_or(&stored_refresh_token.scope);
        self.generate_tokens(
            &client,
            &stored_refresh_token.subject_id,
            stored_refresh_token.subject_type.clone(),
            stored_refresh_token.user_id.as_deref(),
            scope,
            None,
        )
        .await
    }

    async fn handle_client_credentials_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let client = self.get_client(&request.client_id).await?;
        self.validate_client_credentials(&client, request.client_secret.as_deref())?;

        if !client
            .allowed_grant_types
            .contains(&GrantType::ClientCredentials)
        {
            return Err(anyhow!("Client credentials grant is not allowed for this client"));
        }

        let subject_id = client
            .subject_id
            .clone()
            .ok_or_else(|| anyhow!("Client is not bound to an agent subject"))?;

        let scope = request
            .scope
            .as_deref()
            .unwrap_or_else(|| first_scope_or_default(&client));
        self.validate_requested_scope(&client, scope)?;

        self.generate_tokens(&client, &subject_id, SubjectType::Agent, None, scope, None)
            .await
    }

    async fn generate_tokens(
        &self,
        client: &OidcClient,
        subject_id: &str,
        subject_type: SubjectType,
        user_id: Option<&str>,
        scope: &str,
        nonce: Option<&str>,
    ) -> Result<TokenResponse> {
        let now = Utc::now().timestamp();
        let access_token_expires_at = now + client.access_token_lifetime;
        let access_token = self.generate_access_token_jwt(
            &client.client_id,
            subject_id,
            &subject_type,
            user_id,
            scope,
            access_token_expires_at,
        )?;

        let oidc_access_token = OidcAccessToken {
            id: None,
            token: access_token.clone(),
            token_type: "Bearer".to_string(),
            client_id: client.client_id.clone(),
            subject_id: subject_id.to_string(),
            subject_type: subject_type.clone(),
            user_id: user_id.map(str::to_string),
            scope: scope.to_string(),
            expires_at: access_token_expires_at,
            created_at: now,
        };
        self.save_access_token(&oidc_access_token).await?;

        let refresh_token = if client.allowed_grant_types.contains(&GrantType::RefreshToken)
            && subject_type == SubjectType::Human
        {
            let token = generate_random_string(32);
            let refresh_token_expires_at = now + client.refresh_token_lifetime;
            let oidc_refresh_token = OidcRefreshToken {
                id: None,
                token: token.clone(),
                client_id: client.client_id.clone(),
                subject_id: subject_id.to_string(),
                subject_type: subject_type.clone(),
                user_id: user_id.map(str::to_string),
                access_token: access_token.clone(),
                scope: scope.to_string(),
                used: false,
                expires_at: refresh_token_expires_at,
                created_at: now,
            };
            self.save_refresh_token(&oidc_refresh_token).await?;
            Some(token)
        } else {
            None
        };

        let id_token = if scope.contains("openid") && subject_type == SubjectType::Human {
            let user_id = user_id.ok_or_else(|| anyhow!("Human token missing user_id"))?;
            let user = self.get_user_by_id(user_id).await?;
            Some(self.generate_id_token(client, &user, nonce).await?)
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: client.access_token_lifetime,
            refresh_token,
            id_token,
            scope: scope.to_string(),
        })
    }

    async fn generate_id_token(
        &self,
        client: &OidcClient,
        user: &User,
        nonce: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let exp = now + client.id_token_lifetime;

        let claims = IdTokenClaims {
            iss: self.config.app_url.clone(),
            sub: crate::utils::record_id::record_id_key_to_string(
                &user
                    .id
                    .as_ref()
                    .ok_or_else(|| anyhow!("User missing id"))?
                    .clone(),
            ),
            aud: client.client_id.clone(),
            exp,
            iat: now,
            auth_time: user.last_login_at.unwrap_or(now),
            nonce: nonce.map(|n| n.to_string()),
            email: Some(user.email.clone()),
            email_verified: Some(user.is_email_verified),
            name: None,
            preferred_username: Some(user.email.clone()),
            profile: None,
            picture: None,
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.signing_key)
            .map_err(|e| anyhow!("Failed to generate ID token: {e}"))
    }

    pub async fn get_userinfo(&self, access_token: &str) -> Result<UserInfoResponse> {
        let token = self.get_access_token(access_token).await?;
        if token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Access token expired"));
        }
        if token.subject_type != SubjectType::Human {
            return Err(anyhow!("userinfo is only available for human subjects"));
        }

        let user_id = token.user_id.ok_or_else(|| anyhow!("Human token missing user_id"))?;
        let user = self.get_user_by_id(&user_id).await?;

        Ok(UserInfoResponse {
            sub: crate::utils::record_id::record_id_key_to_string(&user.id.unwrap()),
            email: Some(user.email.clone()),
            email_verified: Some(user.is_email_verified),
            name: None,
            preferred_username: Some(user.email),
            profile: None,
            picture: None,
            updated_at: Some(user.updated_at),
        })
    }

    pub async fn get_token_subject_info(
        &self,
        access_token: &str,
    ) -> Result<TokenSubjectInfoResponse> {
        let token = self.get_access_token(access_token).await?;
        if token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Access token expired"));
        }

        Ok(TokenSubjectInfoResponse {
            sub: format!("subject:{}", token.subject_id),
            subject_type: token.subject_type,
            client_id: token.client_id,
            scope: token.scope,
            user_id: token.user_id,
            expires_at: token.expires_at,
        })
    }

    fn validate_client_credentials(
        &self,
        client: &OidcClient,
        provided_secret: Option<&str>,
    ) -> Result<()> {
        match (client.client_type.clone(), provided_secret) {
            (ClientType::Confidential, Some(secret)) => {
                if !self.verify_client_secret(client, secret)? {
                    return Err(anyhow!("Invalid client credentials"));
                }
                Ok(())
            }
            (ClientType::Confidential, None) => Err(anyhow!("Client secret required for confidential clients")),
            (ClientType::Public, Some(secret)) => {
                if !self.verify_client_secret(client, secret)? {
                    return Err(anyhow!("Invalid client credentials"));
                }
                Ok(())
            }
            (ClientType::Public, None) => Ok(()),
        }
    }

    fn validate_requested_scope(&self, client: &OidcClient, scope: &str) -> Result<()> {
        for item in scope.split_whitespace() {
            if !client.allowed_scopes.iter().any(|allowed| allowed == item) {
                return Err(anyhow!("Scope `{item}` is not allowed for this client"));
            }
        }
        Ok(())
    }

    fn verify_client_secret(&self, client: &OidcClient, provided_secret: &str) -> Result<bool> {
        let provided_hash = format!("{:x}", Sha256::digest(provided_secret.as_bytes()));
        Ok(provided_hash == client.client_secret_hash)
    }

    fn verify_pkce(
        &self,
        code_challenge: &str,
        method: &Option<String>,
        code_verifier: &str,
    ) -> Result<bool> {
        match method.as_deref().unwrap_or("plain") {
            "S256" => {
                let hash = Sha256::digest(code_verifier.as_bytes());
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(hash);
                Ok(encoded == code_challenge)
            }
            "plain" => Ok(code_verifier == code_challenge),
            _ => Err(anyhow!("Unsupported code challenge method")),
        }
    }

    fn generate_access_token_jwt(
        &self,
        client_id: &str,
        subject_id: &str,
        subject_type: &SubjectType,
        user_id: Option<&str>,
        scope: &str,
        exp: i64,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            iss: self.config.app_url.clone(),
            sub: format!("subject:{subject_id}"),
            aud: client_id.to_string(),
            exp,
            iat: now,
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            subject_type: subject_type.clone(),
            user_id: user_id.map(str::to_string),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.signing_key)
            .map_err(|e| anyhow!("Failed to generate access token: {e}"))
    }

    async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        let query = "SELECT * FROM oidc_client WHERE client_id = $client_id AND is_active = true LIMIT 1";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("client_id", client_id.to_string()))
            .await?;
        let clients: Vec<OidcClient> = result.take(0)?;
        let mut client = clients
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Client not found"))?;
        client.subject_id = normalize_subject_key(client.subject_id);
        Ok(client)
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        self.db
            .find_record_by_field::<User>("user", "id", user_id)
            .await?
            .ok_or_else(|| anyhow!("User not found"))
    }

    async fn save_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query = r#"
            CREATE oidc_authorization_code CONTENT {
                code: $code,
                client_id: $client_id,
                user_id: type::thing($user_id),
                redirect_uri: $redirect_uri,
                scope: $scope,
                state: $state,
                nonce: $nonce,
                code_challenge: $code_challenge,
                code_challenge_method: $code_challenge_method,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .client
            .query(query)
            .bind(("code", code.code.clone()))
            .bind(("client_id", code.client_id.clone()))
            .bind(("user_id", to_record_literal("user", &code.user_id)))
            .bind(("redirect_uri", code.redirect_uri.clone()))
            .bind(("scope", code.scope.clone()))
            .bind(("state", code.state.clone()))
            .bind(("nonce", code.nonce.clone()))
            .bind(("code_challenge", code.code_challenge.clone()))
            .bind(("code_challenge_method", code.code_challenge_method.clone()))
            .bind(("used", code.used))
            .bind(("expires_at", code.expires_at))
            .bind(("created_at", code.created_at))
            .await?;
        Ok(())
    }

    async fn get_authorization_code(&self, code: &str) -> Result<OidcAuthorizationCode> {
        let query = "SELECT * FROM oidc_authorization_code WHERE code = $code LIMIT 1";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("code", code.to_string()))
            .await?;
        let auth_codes: Vec<OidcAuthorizationCode> = result.take(0)?;
        auth_codes
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Authorization code not found"))
    }

    async fn update_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query = "UPDATE oidc_authorization_code SET used = $used WHERE code = $code";
        self.db
            .client
            .query(query)
            .bind(("code", code.code.clone()))
            .bind(("used", code.used))
            .await?;
        Ok(())
    }

    async fn save_access_token(&self, token: &OidcAccessToken) -> Result<()> {
        let query = r#"
            CREATE oidc_access_token CONTENT {
                token: $token,
                token_type: $token_type,
                client_id: $client_id,
                subject_id: type::thing($subject_id),
                subject_type: $subject_type,
                user_id: $user_id,
                scope: $scope,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .client
            .query(query)
            .bind(("token", token.token.clone()))
            .bind(("token_type", token.token_type.clone()))
            .bind(("client_id", token.client_id.clone()))
            .bind(("subject_id", to_record_literal("subject", &token.subject_id)))
            .bind(("subject_type", token.subject_type.as_str().to_string()))
            .bind((
                "user_id",
                token.user_id.clone().map(|user_id| to_record_literal("user", &user_id)),
            ))
            .bind(("scope", token.scope.clone()))
            .bind(("expires_at", token.expires_at))
            .bind(("created_at", token.created_at))
            .await?;
        Ok(())
    }

    async fn get_access_token(&self, token: &str) -> Result<OidcAccessToken> {
        let query = "SELECT * FROM oidc_access_token WHERE token = $token LIMIT 1";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("token", token.to_string()))
            .await?;
        let mut tokens: Vec<OidcAccessToken> = result.take(0)?;
        let mut access_token = tokens
            .pop()
            .ok_or_else(|| anyhow!("Access token not found"))?;
        access_token.subject_id = normalize_record_key(access_token.subject_id);
        access_token.user_id = access_token.user_id.map(|id| normalize_record_key(id));
        self.validate_access_token_signature(token, &access_token)?;
        Ok(access_token)
    }

    async fn revoke_access_token(&self, token: &str) -> Result<()> {
        let query = "DELETE oidc_access_token WHERE token = $token";
        self.db
            .client
            .query(query)
            .bind(("token", token.to_string()))
            .await?;
        Ok(())
    }

    async fn save_refresh_token(&self, token: &OidcRefreshToken) -> Result<()> {
        let query = r#"
            CREATE oidc_refresh_token CONTENT {
                token: $token,
                client_id: $client_id,
                subject_id: type::thing($subject_id),
                subject_type: $subject_type,
                user_id: $user_id,
                access_token: $access_token,
                scope: $scope,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .client
            .query(query)
            .bind(("token", token.token.clone()))
            .bind(("client_id", token.client_id.clone()))
            .bind(("subject_id", to_record_literal("subject", &token.subject_id)))
            .bind(("subject_type", token.subject_type.as_str().to_string()))
            .bind((
                "user_id",
                token.user_id.clone().map(|user_id| to_record_literal("user", &user_id)),
            ))
            .bind(("access_token", token.access_token.clone()))
            .bind(("scope", token.scope.clone()))
            .bind(("used", token.used))
            .bind(("expires_at", token.expires_at))
            .bind(("created_at", token.created_at))
            .await?;
        Ok(())
    }

    async fn get_refresh_token(&self, token: &str) -> Result<OidcRefreshToken> {
        let query = "SELECT * FROM oidc_refresh_token WHERE token = $token LIMIT 1";
        let mut result = self
            .db
            .client
            .query(query)
            .bind(("token", token.to_string()))
            .await?;
        let mut tokens: Vec<OidcRefreshToken> = result.take(0)?;
        let mut refresh_token = tokens
            .pop()
            .ok_or_else(|| anyhow!("Refresh token not found"))?;
        refresh_token.subject_id = normalize_record_key(refresh_token.subject_id);
        refresh_token.user_id = refresh_token.user_id.map(|id| normalize_record_key(id));
        Ok(refresh_token)
    }

    async fn update_refresh_token(&self, token: &OidcRefreshToken) -> Result<()> {
        let query = "UPDATE oidc_refresh_token SET used = $used WHERE token = $token";
        self.db
            .client
            .query(query)
            .bind(("token", token.token.clone()))
            .bind(("used", token.used))
            .await?;
        Ok(())
    }

    fn validate_access_token_signature(
        &self,
        token: &str,
        stored: &OidcAccessToken,
    ) -> Result<()> {
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(
            token,
            &self.verification_key,
            &jsonwebtoken::Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("Invalid access token signature: {e}"))?;

        let claims = decoded.claims;
        if claims.client_id != stored.client_id
            || claims.scope != stored.scope
            || claims.subject_type != stored.subject_type
            || claims.sub != format!("subject:{}", stored.subject_id)
            || claims.user_id != stored.user_id
        {
            return Err(anyhow!("Access token claims mismatch"));
        }

        Ok(())
    }
}

fn first_scope_or_default(client: &OidcClient) -> &str {
    client.allowed_scopes.first().map(String::as_str).unwrap_or("openid")
}

fn to_record_literal(table: &str, id: &str) -> String {
    if id.contains(':') {
        id.to_string()
    } else {
        format!("{table}:{id}")
    }
}

fn normalize_record_key(value: String) -> String {
    value
        .split_once(':')
        .map(|(_, key)| key.to_string())
        .unwrap_or(value)
}

fn normalize_subject_key(subject_id: Option<String>) -> Option<String> {
    subject_id.map(normalize_record_key)
}

fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::normalize_record_key;

    #[test]
    fn normalize_record_key_handles_plain_and_prefixed_values() {
        assert_eq!(normalize_record_key("subject:abc".to_string()), "abc");
        assert_eq!(normalize_record_key("abc".to_string()), "abc");
    }
}
