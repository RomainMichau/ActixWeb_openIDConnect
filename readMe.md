# Actix-Web openid

Lightweight async OpenID Connect (OIDC) client and middleware for Actix-Web.  
Support for the Authorization Code Flow  
Rely on the excellent [openidconnect-rs](https://github.com/ramosbugs/openidconnect-rs) library for rust

# Example

### Cargo.toml

```toml
[dependencies]
actix_web_openidconnect = "~0.3.0"
```

### main.rs

```rust  
use actix_web::{App, get, HttpResponse, HttpServer, Responder};
use actix_web::dev::ServiceRequest;
use actix_web_openidconnect::ActixWebOpenId;
use actix_web_openidconnect::openid_middleware::Authenticated;

#[get("/no_auth/hello")]
async fn unauth() -> impl Responder {
    HttpResponse::Ok().body("hello unauth_user")
}

#[get("/is_auth/hello")]
async fn auth(auth_data: Authenticated) -> impl Responder {
    HttpResponse::Ok().body(format!("hello auth_user {:?}. email: {:?}", auth_data.access.preferred_username().unwrap(),
                                    auth_data.access.email()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let should_auth = |req: &ServiceRequest| {
        !req.path().starts_with("/no_auth") && req.method() != actix_web::http::Method::OPTIONS
    };
    let openid = ActixWebOpenId::builder(
      "test_client_id".to_string(),
      "http://redirect_url.com/auth".to_string(),
      issuer_url,
    )
            .client_secret("test_client_secret".to_string())
            .should_auth(should_auth)
            .scopes(vec!["openid".to_string()])
            .build_and_init()
            .await
            .unwrap();
    HttpServer::new(move || App::new()
        .wrap(openid.get_middleware())
        .configure(openid.configure_open_id())
        .service(unauth)
        .service(auth)
    )
        .bind(("0.0.0.0", 8081))?

        .run()
        .await
}
```  

# Parameters

| name                     | description                                                                                                                                                                                               | Example                                                                                                                        | doc                                                                                                                  |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| client_id                | The client id of the application as defined on your OIDC provider                                                                                                                                         | "client_id"                                                                                                                    | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-oidc-client_server_administration_guide) |
| client_secret            | The client secret of the application as defined on your OIDC provider                                                                                                                                     | "client_secret"                                                                                                                | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-oidc-client_server_administration_guide) |
| redirect_url             | The uri to redirect to after the OIDC provider has authenticated the user. Path need to be /auth_callback. Usually need to be registered in the OIDC Provider                                             | "http://localhost:8080/auth_callback"                                                                                          | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#con-basic-settings_server_administration_guide)        |
| issuer_url               | URL of the OIDC provider                                                                                                                                                                                  | "https://my_keycloak.com/realms/my_realm"                                                                                      |                                                                                                                      |
| should_auth              | Closure taking an `actix_web::service::ServiceRequest` in input and returning a boolean. If true the request will need to be authenticate. Allows you to configure which endpoint should be authenticated | ``` \|req: &ServiceRequest\| {  !req.path().starts_with("/no_auth") && !req.method() == actix_web::http::Method::OPTIONS };``` |                                                                                                                      |
| post_logout_redirect_url | Optional url on which the user will be redirected after a logout. Usually need to be registered in the OIDC provider                                                                                      | "http://localhost:8080"                                                                                                        | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#con-basic-settings_server_administration_guide)        |
| scopes                   | List of scope to be used during the authentication. "openid" scope is required for openid flow                                                                                                            | [openid, profile, email]                                                                                                       | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#_client_scopes)                                        |
| use_pkce                 | Enforce the usage of PKCE (Proof Key for Code Exchange Code Challenge Method). Need to be supported by the OIDC provider                                                                                  | `true`                                                                                                                         | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-oidc-client_server_administration_guide) |
| additional_audiences     | Additional audiences claims trusted by client                                                                                                                                                             | [myOtherClient1, myOtherClient2]                                                                                               | [keycloak](https://www.keycloak.org/docs/latest/authorization_services/index.html)                                   |

# Features

### Authentication middleware

Add a middleware checking user authentication information, and authenticate the user if needed.  
Make authentication information available to the endpoint handler

### Login

Automatically redirect the user to the OIDC provider when requiring authentication.  
Open a callback endpoint (/auth_callback) to redirect the user at the end of the authorization code flow
Will store access token, refresh token, id_token and user info in cookies

### Logout

Open a logout endpoint (/logout). Calling this endpoint will automatically redirect the user to the openID connect
logout

### Front end

Make user info contained in the ID token available to the front end through a cookie user_info

# Disclaimer

## Metadata

This library expect 1 additional metadata to be available on the OIDC provider from what is defined in
the [OIDC RFC](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata):

- `end_session_endpoint`: The OIDC provider logout
  endpoint. (https://openid.net/specs/openid-connect-session-1_0-17.html)
  This metadata is available in all modern OIDC provider metadata endpoint (keycloak, okta, auth0...)

## Access token

This library is for now agnostic from the Access Token format and use the /userinfo endpoint to get user information and
validate this token  
This is mainly because the openidconnect-rs library stick to the OIDC RFC which does not define the access token
format.  
However, as the de-facto standard for access token format is JWT (https://datatracker.ietf.org/doc/html/rfc9068) the
library should be updated to support access token signature it in the future

# TODO

- [x] Add support for PKCE. (Done, thanks to [@DerKnerd](https://github.com/DerKnerd))
- [ ] Add support for refresh token
- [ ] Add support for JWT access token (https://datatracker.ietf.org/doc/html/rfc9068)
