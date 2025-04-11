use anyhow::Result;
use oauth2::basic::{BasicErrorResponseType, BasicRevocationErrorResponse};
use oauth2::{
    EndpointMaybeSet, EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier,
    StandardErrorResponse, StandardRevocableToken,
};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClaimName, CoreClaimType,
    CoreClient, CoreClientAuthMethod, CoreGenderClaim, CoreGrantType, CoreIdTokenClaims,
    CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
    CoreTokenIntrospectionResponse, CoreTokenResponse,
};
use openidconnect::{reqwest, Client, IdToken};
use openidconnect::{
    AccessToken, AdditionalProviderMetadata, AuthorizationCode, ClaimsVerificationError, ClientId,
    ClientSecret, CsrfToken, EmptyAdditionalClaims, EndSessionUrl, IssuerUrl, LogoutRequest, Nonce,
    OAuth2TokenResponse, PostLogoutRedirectUrl, ProviderMetadata, RedirectUrl, RefreshToken, Scope,
    TokenResponse, UserInfoClaims,
};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use url::Url;

#[derive(Clone)]
pub struct OpenID {
    client: ExtendedClient,
    provider_metadata: ExtendedProviderMetadata,
    post_logout_redirect_url: Option<String>,
    scopes: Vec<Scope>,
    additional_audiences: Vec<String>,
    pub(crate) use_pkce: bool,
}

pub struct OpenIDTokens {
    pub access_token: AccessToken,
    pub id_token: Option<ExtendedIdToken>,
    pub refresh_token: Option<RefreshToken>,
}

pub struct AuthorizationUrl {
    pub url: Url,
    pub nonce: Nonce,
    pub pkce_verifier: Option<String>,
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
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub(crate) type ExtendedClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<BasicErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub(crate) type ExtendedIdToken = IdToken<
    EmptyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

fn get_http_client() -> reqwest::Client {
    reqwest::Client::builder().build().unwrap()
}

impl OpenID {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn init(
        client_id: String,
        client_secret: Option<String>,
        redirect_uri: String,
        issuer_url: String,
        post_logout_redirect_url: Option<String>,
        scopes: Vec<String>,
        additional_audiences: Vec<String>,
        use_pkce: bool,
    ) -> Result<Self> {
        let provider_metadata = ExtendedProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url)?,
            &get_http_client(),
        )
        .await
        .expect("Failed to discover OpenID Provider");

        let client = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
            ClientId::new(client_id.to_string()),
            client_secret.map(|client_secret| ClientSecret::new(client_secret.to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string()).expect("Invalid redirect URL"),
        );

        Ok(Self {
            client,
            provider_metadata,
            post_logout_redirect_url,
            scopes: scopes.iter().map(|s| Scope::new(s.to_string())).collect(),
            additional_audiences,
            use_pkce,
        })
    }

    pub(crate) fn get_authorization_url(&self, path: String, with_pkce: bool) -> AuthorizationUrl {
        let builder = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(path.clone()),
                Nonce::new_random,
            )
            .add_scopes(self.scopes.clone());
        if with_pkce {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            let (url, .., nonce) = builder.set_pkce_challenge(pkce_challenge).url();

            AuthorizationUrl {
                url,
                nonce,
                pkce_verifier: Some(pkce_verifier.secret().clone()),
            }
        } else {
            let (url, .., nonce) = builder.url();
            AuthorizationUrl {
                url,
                nonce,
                pkce_verifier: None,
            }
        }
    }

    pub(crate) async fn get_token(
        &self,
        authorization_code: AuthorizationCode,
        pkce_verifier: Option<String>,
    ) -> Result<OpenIDTokens> {
        let token_response = if let Some(pkce_verifier) = pkce_verifier {
            self.client
                .exchange_code(authorization_code)?
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        } else {
            self.client.exchange_code(authorization_code)?
        }
        .request_async(&get_http_client())
        .await?;

        let id_token = token_response.id_token().cloned();

        Ok(OpenIDTokens {
            access_token: token_response.access_token().clone(),
            id_token,
            refresh_token: token_response.refresh_token().cloned(),
        })
    }

    pub(crate) async fn user_info(
        &self,
        access_token: AccessToken,
    ) -> Result<UserInfoClaims<EmptyAdditionalClaims, CoreGenderClaim>> {
        Ok(self
            .client
            .user_info(access_token, None)?
            .request_async(&get_http_client())
            .await?)
    }

    pub(crate) async fn verify_id_token<'a>(
        &self,
        id_token: &'a ExtendedIdToken,
        nonce: String,
    ) -> Result<&'a CoreIdTokenClaims, ClaimsVerificationError> {
        id_token.claims(
            &self
                .client
                .id_token_verifier()
                .set_other_audience_verifier_fn(|aud| self.additional_audiences.contains(aud)),
            &Nonce::new(nonce),
        )
    }

    pub(crate) fn get_logout_uri(&self, id_token: &ExtendedIdToken) -> Url {
        let mut logout_request = LogoutRequest::from(
            self.provider_metadata
                .additional_metadata()
                .end_session_endpoint
                .clone()
                .unwrap(),
        )
        .set_id_token_hint(id_token);

        if let Some(ref uri) = self.post_logout_redirect_url {
            logout_request = logout_request
                .set_post_logout_redirect_uri(PostLogoutRedirectUrl::new(uri.to_string()).unwrap());
        }

        logout_request.http_get_url()
    }
}
