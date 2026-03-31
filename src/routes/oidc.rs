use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Extension, Form, Query},
    http::{header, HeaderMap},
    response::{Json, Redirect},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use serde_json::json;

use crate::{
    config::Config,
    error::AuthError,
    models::oidc_token::{
        AuthorizeRequest, TokenRequest, TokenSubjectInfoResponse, UserInfoResponse,
    },
    services::{
        database::Database,
        oidc::{JwksResponse, OidcConfiguration, OidcService},
    },
    utils::jwt::get_user_from_token,
};

pub fn oidc_routes() -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/me", get(me))
        .route("/logout", get(logout))
}

async fn openid_configuration(
    Extension(oidc_service): Extension<Arc<OidcService>>,
) -> Result<Json<OidcConfiguration>, AuthError> {
    Ok(Json(oidc_service.get_configuration()))
}

async fn jwks(
    Extension(_oidc_service): Extension<Arc<OidcService>>,
) -> Result<Json<JwksResponse>, AuthError> {
    Ok(Json(JwksResponse { keys: vec![] }))
}

async fn authorize(
    Query(params): Query<HashMap<String, String>>,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(db): Extension<Arc<Database>>,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    let request = AuthorizeRequest {
        response_type: params
            .get("response_type")
            .ok_or_else(|| AuthError::BadRequest("Missing response_type".to_string()))?
            .clone(),
        client_id: params
            .get("client_id")
            .ok_or_else(|| AuthError::BadRequest("Missing client_id".to_string()))?
            .clone(),
        redirect_uri: params
            .get("redirect_uri")
            .ok_or_else(|| AuthError::BadRequest("Missing redirect_uri".to_string()))?
            .clone(),
        scope: params.get("scope").cloned(),
        state: params.get("state").cloned(),
        nonce: params.get("nonce").cloned(),
        code_challenge: params.get("code_challenge").cloned(),
        code_challenge_method: params.get("code_challenge_method").cloned(),
        prompt: params.get("prompt").cloned(),
        max_age: params.get("max_age").and_then(|s| s.parse().ok()),
    };

    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(user) = get_user_from_token(token, &db).await {
                    match oidc_service
                        .create_authorization_code(
                            &request,
                            &crate::utils::record_id::record_id_key_to_string(&user.id.unwrap()),
                        )
                        .await
                    {
                        Ok(code) => {
                            let mut redirect_url = format!("{}?code={code}", request.redirect_uri);
                            if let Some(state) = request.state {
                                redirect_url.push_str(&format!("&state={state}"));
                            }
                            return Ok(Redirect::to(&redirect_url));
                        }
                        Err(e) => {
                            let error_url = format!(
                                "{}?error=server_error&error_description={}",
                                request.redirect_uri,
                                urlencoding::encode(&e.to_string())
                            );
                            return Ok(Redirect::to(&error_url));
                        }
                    }
                }
            }
        }
    }

    let login_url = format!("/login?{}", serde_urlencoded::to_string(&params).unwrap_or_default());
    Ok(Redirect::to(&login_url))
}

async fn token(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
    Form(mut request): Form<TokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    if request.client_secret.is_none() {
        if let Ok((client_id, client_secret)) = authenticate_client(&headers) {
            if request.client_id.is_empty() {
                request.client_id = client_id;
            }
            request.client_secret = Some(client_secret);
        }
    }

    match oidc_service.exchange_code_for_tokens(&request).await {
        Ok(token_response) => Ok(Json(serde_json::to_value(token_response)?)),
        Err(e) => {
            let error_response = json!({
                "error": "invalid_request",
                "error_description": e.to_string()
            });
            Err(AuthError::BadRequest(error_response.to_string()))
        }
    }
}

async fn userinfo(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, AuthError> {
    let access_token = extract_bearer_token(&headers)?;

    match oidc_service.get_userinfo(access_token).await {
        Ok(userinfo) => Ok(Json(userinfo)),
        Err(e) => Err(AuthError::Unauthorized(e.to_string())),
    }
}

async fn me(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
) -> Result<Json<TokenSubjectInfoResponse>, AuthError> {
    let access_token = extract_bearer_token(&headers)?;

    match oidc_service.get_token_subject_info(access_token).await {
        Ok(info) => Ok(Json(info)),
        Err(e) => Err(AuthError::Unauthorized(e.to_string())),
    }
}

async fn logout(
    Query(params): Query<HashMap<String, String>>,
    Extension(config): Extension<Arc<Config>>,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri");
    let state = params.get("state");

    let redirect_url = if let Some(redirect_uri) = post_logout_redirect_uri {
        let mut url = redirect_uri.clone();
        if let Some(state_value) = state {
            url.push_str(&format!("?state={state_value}"));
        }
        url
    } else {
        config.app_url.clone()
    };

    Ok(Redirect::to(&redirect_url))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AuthError::Unauthorized("Missing authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| AuthError::Unauthorized("Invalid authorization header".to_string()))?;

    auth_str
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::Unauthorized("Invalid token type".to_string()))
}

fn authenticate_client(headers: &HeaderMap) -> Result<(String, String), AuthError> {
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                    if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            return Ok((parts[0].to_string(), parts[1].to_string()));
                        }
                    }
                }
            }
        }
    }

    Err(AuthError::Unauthorized("Missing client credentials".to_string()))
}
