use std::fmt::Debug;

use anyhow::Result;
use openidconnect::{AccessToken, AdditionalProviderMetadata, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EndSessionUrl, IdTokenClaims, IssuerUrl, LogoutRequest, Nonce, OAuth2TokenResponse, PostLogoutRedirectUrl, ProviderMetadata, RedirectUrl, RefreshToken, Scope, TokenResponse, UserInfoClaims};
use openidconnect::core::{CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType, CoreClient, CoreClientAuthMethod, CoreGenderClaim, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType};
use openidconnect::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone)]
pub struct OpenID {
    client: CoreClient,
    provider_metadata: ExtendedProviderMetadata,
    post_logout_redirect_url: Option<String>,
    scopes: Vec<Scope>,
}

pub struct OpenIDTokens {
    pub access_token: AccessToken,
    pub id_token: IdToken,
    pub refresh_token: Option<RefreshToken>,
}


pub struct AuthorizationUrl {
    pub url: Url,
    pub nonce: Nonce,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdditionalMetadata {
    end_session_endpoint: Option<EndSessionUrl>,
}


impl AdditionalProviderMetadata for AdditionalMetadata {}

pub type ExtendedProviderMetadata = ProviderMetadata<
    AdditionalMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub(crate) type IdToken = openidconnect::IdToken<EmptyAdditionalClaims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreJsonWebKeyType>;

impl OpenID {
    pub(crate) async fn init(client_id: String, client_secret: String, redirect_uri: String, issuer_url: String,
                             post_logout_redirect_url: Option<String>, scopes: Vec<String>) -> Result<Self> {
        let provider_metadata = ExtendedProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url)?,
            async_http_client,
        ).await?;
        let client = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
        )
            .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?);
        Ok(
            Self {
                client,
                provider_metadata,
                post_logout_redirect_url,
                scopes: scopes.iter().map(|s| Scope::new(s.to_string())).collect(),
            }
        )
    }


    pub(crate) fn get_authorization_url(&self, path: String) -> AuthorizationUrl {
        let authorize_url_builder = self.client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(path.clone()),
                Nonce::new_random,
            ).add_scopes(self.scopes.clone());
        let (auth_url, _csrf_token, nonce) = authorize_url_builder.url();

        AuthorizationUrl {
            url: auth_url,
            nonce,
        }
    }

    pub(crate) async fn get_token(&self, authorization_code: AuthorizationCode) -> Result<OpenIDTokens> {
        let token_response = self.client
            .exchange_code(authorization_code)
            .request_async(async_http_client)
            .await?;
        let id_token = token_response.id_token().cloned();
        Ok(OpenIDTokens {
            access_token: token_response.access_token().clone(),
            id_token: id_token.unwrap(),
            refresh_token: token_response.refresh_token().cloned(),
        })
    }

    pub(crate) async fn user_info(&self, access_token: AccessToken) -> Result<UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>> {
        Ok(self.client.user_info(access_token, None)?.request_async(async_http_client).await?)
    }

    pub(crate) async fn verify_id_token<'a>(&self, id_token: &'a IdToken, nonce: String) -> Result<&'a IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>, ClaimsVerificationError> {
        id_token.claims(&self.client.id_token_verifier(), &Nonce::new(nonce))
    }

    pub(crate) fn get_logout_uri(&self, id_token: &IdToken) -> Url {
        let mut logout_request = LogoutRequest::from(self.provider_metadata.additional_metadata().end_session_endpoint.clone().unwrap())
            .set_id_token_hint(id_token);
        match &self.post_logout_redirect_url {
            None => {}
            Some(uri) => {
                logout_request = logout_request.set_post_logout_redirect_uri(PostLogoutRedirectUrl::new(uri.to_string()).unwrap());
            }
        };
        logout_request.http_get_url()
    }
}

