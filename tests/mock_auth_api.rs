use actix_http::Request;
use actix_service::Service;
use actix_web::{
    dev::ServiceResponse,
    get,
    test::{self},
    App, Error, HttpResponse, Responder,
};

use actix_web_openidconnect::openid_middleware::Authenticated;
use actix_web_openidconnect::ActixWebOpenId;

#[get("/no_auth/hello")]
pub async fn unauth() -> impl Responder {
    HttpResponse::Ok().body("hello unauth_user")
}

#[get("/is_auth/hello")]
async fn auth(auth_data: Authenticated) -> impl Responder {
    HttpResponse::Ok().body(format!(
        "hello auth_user {:?}. email: {:?}",
        auth_data.access.preferred_username().unwrap(),
        auth_data.access.email()
    ))
}

pub(crate) async fn get_mock_auth_api(
    oidc: &ActixWebOpenId,
) -> impl Service<Request, Response = ServiceResponse, Error = Error> {
    let app = test::init_service(
        App::new()
            .wrap(oidc.get_middleware())
            .service(unauth)
            .service(auth)
            .configure(oidc.configure_open_id()),
    )
    .await;
    app
}
