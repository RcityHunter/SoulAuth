use std::sync::Arc;
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    models::{
        oidc_client::{CreateOidcClientRequest, OidcClientResponse},
    },
    services::{
        oidc_client_management::OidcClientService,
        database::Database,
    },
    error::AuthError,
};

pub fn oidc_client_routes() -> Router {
    Router::new()
        .route("/clients", post(create_client))
        .route("/clients", get(list_clients))
        .route("/clients/:client_id", get(get_client))
        .route("/clients/:client_id", put(update_client))
        .route("/clients/:client_id", delete(disable_client))
        .route("/clients/:client_id/regenerate-secret", post(regenerate_secret))
}

#[derive(Deserialize)]
struct ListClientsQuery {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize)]
struct ListClientsResponse {
    clients: Vec<OidcClientResponse>,
    total: i32,
    limit: i32,
    offset: i32,
}

#[derive(Serialize)]
struct RegenerateSecretResponse {
    client_secret: String,
    message: String,
}

// 创建 OIDC 客户端
async fn create_client(
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    // 验证请求数据
    request.validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;

    // TODO: 从请求中获取当前用户（需要认证中间件）
    let created_by = "system"; // 临时使用系统用户

    // 检查权限
    // require_permission("oidc_clients.write").await?;

    match client_service.create_client(request, created_by).await {
        Ok(client) => Ok(Json(client)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取客户端列表
async fn list_clients(
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Query(query): Query<ListClientsQuery>,
) -> Result<Json<ListClientsResponse>, AuthError> {
    // 检查权限
    // require_permission("oidc_clients.read").await?;

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match client_service.list_clients(Some(limit), Some(offset)).await {
        Ok(clients) => {
            let total = clients.len() as i32; // 这里应该从数据库获取总数
            Ok(Json(ListClientsResponse {
                clients,
                total,
                limit,
                offset,
            }))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取单个客户端
async fn get_client(
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    // 检查权限
    // require_permission("oidc_clients.read").await?;

    match client_service.get_client(&client_id).await {
        Ok(client) => {
            let response = OidcClientResponse {
                client_id: client.client_id,
                subject_id: client.subject_id,
                client_secret: "***".to_string(), // 不返回密钥
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
            };
            Ok(Json(response))
        }
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 更新客户端
async fn update_client(
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    // 验证请求数据
    request.validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;

    // 检查权限
    // require_permission("oidc_clients.write").await?;

    match client_service.update_client(&client_id, request).await {
        Ok(client) => Ok(Json(client)),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 禁用客户端
async fn disable_client(
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    // 检查权限
    // require_permission("oidc_clients.delete").await?;

    match client_service.disable_client(&client_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 重新生成客户端密钥
async fn regenerate_secret(
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<RegenerateSecretResponse>, AuthError> {
    // 检查权限
    // require_permission("oidc_clients.write").await?;

    match client_service.regenerate_client_secret(&client_id).await {
        Ok(new_secret) => {
            let response = RegenerateSecretResponse {
                client_secret: new_secret,
                message: "Client secret has been regenerated. Please update your application configuration.".to_string(),
            };
            Ok(Json(response))
        }
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}