//! Actix Web is a powerful, pragmatic, and extremely fast web framework for Rust.
//!
//! # Examples
//! Lightweight async OpenID Connect (OIDC) client and middleware for Actix-Web.
//! Support for the Authorization Code Flow
//! Documentation: https://github.com/RomainMichau/ActixWeb_openIDConnect
//!

use std::sync::Arc;

use actix_web::dev::ServiceRequest;
use actix_web::web;
use actix_web::web::ServiceConfig;

use crate::openid::OpenID;

mod openid;
pub mod openid_middleware;

#[derive(Clone)]
pub struct ActixWebOpenId {
    openid_client: Arc<OpenID>,
    should_auth: fn(&ServiceRequest) -> bool,
    use_pkce: bool,
}

pub struct ActixWebOpenIdBuilder {
    client_id: String,
    client_secret: Option<String>,
    redirect_url: String,
    issuer_url: String,
    should_auth: fn(&ServiceRequest) -> bool,
    post_logout_redirect_url: Option<String>,
    scopes: Vec<String>,
    additional_audiences: Vec<String>,
    use_pkce: bool,
    redirect_on_error: bool,
    allow_all_audiences: bool,
}

impl ActixWebOpenIdBuilder {
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    pub fn should_auth(mut self, f: fn(&ServiceRequest) -> bool) -> Self {
        self.should_auth = f;
        self
    }

    pub fn post_logout_redirect_url(mut self, url: impl Into<String>) -> Self {
        self.post_logout_redirect_url = Some(url.into());
        self
    }

    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn additional_audiences(mut self, audiences: Vec<String>) -> Self {
        self.additional_audiences = audiences;
        self
    }

    pub fn use_pkce(mut self, pkce: bool) -> Self {
        self.use_pkce = pkce;
        self
    }

    pub fn redirect_on_error(mut self, redirect_on_error: bool) -> Self {
        self.redirect_on_error = redirect_on_error;
        self
    }

    pub fn allow_all_audiences(mut self, allow_all_audiences: bool) -> Self {
        self.allow_all_audiences = allow_all_audiences;
        self
    }

    pub async fn build_and_init(self) -> anyhow::Result<ActixWebOpenId> {
        Ok(ActixWebOpenId {
            openid_client: Arc::new(
                OpenID::init(
                    self.client_id,
                    self.client_secret,
                    self.redirect_url,
                    self.issuer_url,
                    self.post_logout_redirect_url,
                    self.scopes,
                    self.additional_audiences,
                    self.use_pkce,
                    self.redirect_on_error,
                    self.allow_all_audiences,
                )
                .await?,
            ),
            should_auth: self.should_auth,
            use_pkce: self.use_pkce,
        })
    }
}

impl ActixWebOpenId {
    pub fn builder(
        client_id: String,
        redirect_url: String,
        issuer_url: String,
    ) -> ActixWebOpenIdBuilder {
        ActixWebOpenIdBuilder {
            client_id,
            client_secret: None,
            redirect_url,
            issuer_url,
            should_auth: |_| true, // default behavior
            post_logout_redirect_url: None,
            scopes: vec!["openid".into()],
            additional_audiences: vec![],
            use_pkce: false,
            redirect_on_error: false,
            allow_all_audiences: false,
        }
    }

    pub fn configure_open_id(&self) -> impl Fn(&mut ServiceConfig) {
        let client = self.openid_client.clone();
        move |cfg: &mut ServiceConfig| {
            cfg.service(openid_middleware::auth_endpoint)
                .service(openid_middleware::logout_endpoint)
                .app_data(web::Data::new(client.clone()));
        }
    }

    pub fn get_middleware(&self) -> openid_middleware::AuthenticateMiddlewareFactory {
        openid_middleware::AuthenticateMiddlewareFactory::new(
            self.openid_client.clone(),
            self.should_auth,
            self.use_pkce,
        )
    }
}
