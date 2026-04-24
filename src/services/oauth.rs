use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl,
    ClientId,
    ClientSecret,
    RedirectUrl,
    TokenUrl,
    Scope,
    CsrfToken,
    TokenResponse,
};
use serde::Deserialize;
use tracing::{error, info};
use reqwest::{Client, Proxy};

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub struct OAuthService {
    config: Config,
    google_client: BasicClient,
    github_client: BasicClient,
}

impl OAuthService {
    pub fn new(config: Config) -> Result<Self> {
        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/google", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/github", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        Ok(Self {
            config,
            google_client,
            github_client,
        })
    }

    // 创建一个配置了代理的 HTTP 客户端
    fn create_http_client(&self) -> Result<Client> {
        let mut client_builder = Client::builder()
            .danger_accept_invalid_certs(true);  // 允许自签名证书
        
        if self.config.proxy_enabled {
            if let Some(proxy_url) = &self.config.proxy_url {
                let proxy_url = proxy_url.replace("https://", "http://");  // 强制使用 http 协议
                info!("Using proxy: {}", proxy_url);
                client_builder = client_builder.proxy(
                    Proxy::all(&proxy_url)
                        .map_err(|e| AuthError::OAuthError(format!("Failed to create proxy: {}", e)))?
                );
            }
        }

        client_builder
            .build()
            .map_err(|e| AuthError::OAuthError(format!("Failed to create HTTP client: {}", e)))
    }

    pub fn get_google_auth_url(&self) -> Result<String> {
        let (auth_url, _) = self.google_client
            .authorize_url(|| CsrfToken::new(uuid::Uuid::new_v4().to_string()))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<OAuthUserInfo> {
        info!("Starting Google OAuth callback with code: {}", code);
        
        // 交换授权码获取访问令牌
        info!("Exchanging authorization code for access token");
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            self.google_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        } else {
            self.google_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        }.map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 使用访问令牌获取用户信息
        info!("Fetching user info from Google API");
        let client = if self.config.proxy_enabled {
            self.create_http_client()?
        } else {
            Client::new()
        };

        let user_info: GoogleUserInfo = match client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(token.access_token().secret())
            .send()
            .await {
                Ok(response) => {
                    info!("Received response from Google API");
                    match response.json().await {
                        Ok(info) => {
                            info!("Successfully parsed user info");
                            info
                        },
                        Err(e) => {
                            error!("Failed to parse user info: {}", e);
                            return Err(AuthError::OAuthError(e.to_string()));
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to fetch user info: {}", e);
                    return Err(AuthError::OAuthError(e.to_string()));
                }
            };

        if !user_info.verified_email {
            error!("User email is not verified");
            return Err(AuthError::EmailNotVerified);
        }

        info!("Successfully completed Google OAuth callback for user: {}", user_info.email);
        Ok(OAuthUserInfo {
            provider: "google".to_string(),
            provider_user_id: user_info.id,
            email: user_info.email,
            name: user_info.name,
            picture: user_info.picture,
        })
    }

    pub fn get_github_auth_url(&self) -> Result<String> {
        let (auth_url, _) = self
            .github_client
            .authorize_url(|| CsrfToken::new(uuid::Uuid::new_v4().to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            self.github_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        } else {
            self.github_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        }.map_err(|e| AuthError::OAuthError(e.to_string()))?;

        let client = if self.config.proxy_enabled {
            self.create_http_client()?
        } else {
            Client::new()
        };
        
        // 获取用户信息
        let user_info: GitHubUserInfo = client
            .get("https://api.github.com/user")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "soulauth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取用户邮箱（因为某些用户可能没有公开邮箱）
        let emails: Vec<GitHubEmail> = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "soulauth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取主要且已验证的邮箱
        let primary_email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| AuthError::EmailNotVerified)?;

        Ok(OAuthUserInfo {
            provider: "github".to_string(),
            provider_user_id: user_info.id.to_string(),
            email: primary_email.email,
            name: user_info.name,
            picture: user_info.avatar_url,
        })
    }
}
