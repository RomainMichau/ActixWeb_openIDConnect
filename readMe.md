# Actix-Web openid
Lightweight async OpenID Connect (OIDC) client and middleware for Actix-Web.  
Support for the Authorization Code Flow

# Example
```rust  
use actix_web::{App, get, HttpResponse, HttpServer, Responder};  
use actix_web::dev::ServiceRequest;  
use actix_web_openid::openid_middleware::Authenticated;  
use actix_web_openid::TokenIntrospectionResponse;  
#[get("/no_auth/hello")]  
async fn unauth() -> impl Responder {  
    HttpResponse::Ok().body("hello unauth_user")  
}  
  
#[get("/is_auth/hello")]  
// As the endpoint is authenticated, you can access user info with auth_data: Authenticated
async fn auth(auth_data: Authenticated) -> impl Responder {  
    HttpResponse::Ok().body(format!("hello auth_user {:?}. Scopes: {:?}", auth_data.access.username().unwrap(),  
                                    auth_data.access.scopes()))  
}  
  
#[actix_web::main]  
async fn main() -> std::io::Result<()> {  
    env_logger::init();  
    let should_auth = |req: &ServiceRequest| {  
        !req.path().starts_with("/no_auth") && !req.method() == actix_web::http::Method::OPTIONS  
    };  
    let openid = actix_web_openid::ActixWebOpenId::init("client_id".to_string(),  
                                                        "client_secret".to_string(),  
                                                        "http://localhost:8080/auth_callback".to_string(),  
                                                        "https://my_keycloak.com/realms/my_realm".to_string(),  
                                                        should_auth,  
                                                        Some("/is_auth/hello/yo".to_string()),  
                                                        vec!["openid".to_string()]).await;  
    HttpServer::new(move || App::new()  
        .wrap(openid.get_middleware())  // Add the authentication middleware
        .configure(openid.configure_open_id())   // Add the authentication and logout route
        .service(unauth)  
        .service(auth)  
    )  
        .bind(("0.0.0.0", 8081))?  
  
  .run()  
        .await  
}
```  
# Parameters


| name | description | Example | doc |
|--|--|--|--|
| client_id | The client id of the application as defined on your OIDC provider |"client_id"|[keycloak](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-oidc-client_server_administration_guide)
|client_secret|The client secret of the application as defined on your OIDC provider| "client_secret"| [keycloak](https://www.keycloak.org/docs/latest/server_admin/#proc-creating-oidc-client_server_administration_guide)
|redirect_url| The uri to redirect to after the OIDC provider has authenticated the user. Path need to be /auth_callback. Usually need to be registered in the OIDC Provider | "http://localhost:8080/auth_callback" | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#con-basic-settings_server_administration_guide)
|issuer_url| URL of the OIDC provider | "https://my_keycloak.com/realms/my_realm" | |
should_auth| Closure taking an `actix_web::service::ServiceRequest` in input and returning a boolean. If true the request will need to be authenticate. Allows you to configure which endpoint should be authenticated | ``` \|req: &ServiceRequest\| {  !req.path().starts_with("/no_auth") && !req.method() == actix_web::http::Method::OPTIONS };``` |
post_logout_redirect_url| Optional url on which the user will be redirected after a logout. Usually need to be registered in the OIDC provider | "http://localhost:8080" | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#con-basic-settings_server_administration_guide)|
scopes|List of scope to be used during the authentication. "openid" scope is required for openid flow | [openid, profile, email] | [keycloak](https://www.keycloak.org/docs/latest/server_admin/#_client_scopes)

# Features
### Authentication middleware
Add a middleware checking user authentication information, and authenticate the user if needed.  
Make authentication information available to the endpoint handler
### Login
Automatically redirect the user to the OIDC provider when requiring authentication.  
Open a callback endpoint (/auth_callback) to redirect the user at the end of the authorization code flow
Will store access token, refresh token, id_token and user info in cookies
### Logout
Open a logout endpoint (/logout). Calling this endpoint will automatically redirect the user to the openID connect logout
### Front end
Make user info contained in the ID token available to the front end through a cookie user_info
