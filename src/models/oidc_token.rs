use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

use crate::models::subject::SubjectType;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct OidcAuthorizationCode {
    pub id: Option<String>,
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub used: bool,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct OidcAccessToken {
    pub id: Option<String>,
    pub token: String,
    pub token_type: String,
    pub client_id: String,
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub user_id: Option<String>,
    pub scope: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct OidcRefreshToken {
    pub id: Option<String>,
    pub token: String,
    pub client_id: String,
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub user_id: Option<String>,
    pub access_token: String,
    pub scope: String,
    pub used: bool,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub client_id: String,
    pub scope: String,
    pub subject_type: SubjectType,
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenSubjectInfoResponse {
    pub sub: String,
    pub subject_type: SubjectType,
    pub client_id: String,
    pub scope: String,
    pub user_id: Option<String>,
    pub expires_at: i64,
}
