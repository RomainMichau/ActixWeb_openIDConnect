use actix_web::{App, get, HttpResponse, HttpServer, Responder};
use actix_web::dev::ServiceRequest;
use actix_web_openid::openid_middleware::Authenticated;
use actix_web_openid::TokenIntrospectionResponse;
#[get("/no_auth/hello")]
async fn unauth() -> impl Responder {
    HttpResponse::Ok().body("hello unauth_user")
}

#[get("/is_auth/hello")]
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
        .wrap(openid.get_middleware())
        .configure(openid.configure_open_id())
        .service(unauth)
        .service(auth)
    )
        .bind(("0.0.0.0", 8081))?

        .run()
        .await
}