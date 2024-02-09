use actix_http::body::MessageBody;
use actix_http::header::HeaderMap;
use actix_web::dev::ServiceResponse;
use actix_web::web::{Buf, Bytes};
use actix_web::Error;
use actix_web_openidconnect::ActixWebOpenId;
use httpmock::Method::GET;
use httpmock::{Mock, MockServer};
use url::Url;

mod mock_auth_api;

static METADATA: &str = "{\"issuer\":\"https://base_url/realms/my_realm\",\"authorization_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/auth\",\"token_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/token\",\"introspection_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/token/introspect\",\"userinfo_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/userinfo\",\"end_session_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/logout\",\"frontchannel_logout_session_supported\":true,\"frontchannel_logout_supported\":true,\"jwks_uri\":\"https://base_url/realms/my_realm/protocol/openid-connect/certs\",\"check_session_iframe\":\"https://base_url/realms/my_realm/protocol/openid-connect/login-status-iframe.html\",\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\",\"urn:openid:params:grant-type:ciba\",\"urn:ietf:params:oauth:grant-type:device_code\"],\"acr_values_supported\":[\"0\",\"1\"],\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"subject_types_supported\":[\"public\",\"pairwise\"],\"id_token_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"id_token_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"userinfo_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"],\"userinfo_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"userinfo_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"request_object_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"],\"request_object_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"request_object_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\",\"query.jwt\",\"fragment.jwt\",\"form_post.jwt\",\"jwt\"],\"registration_endpoint\":\"https://base_url/realms/my_realm/clients-registrations/openid-connect\",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"introspection_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"],\"introspection_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"authorization_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"authorization_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"],\"authorization_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"],\"claims_supported\":[\"aud\",\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\",\"acr\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"scopes_supported\":[\"openid\",\"address\",\"roles\",\"acr\",\"email\",\"phone\",\"web-origins\",\"offline_access\",\"microprofile-jwt\",\"profile\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":true,\"code_challenge_methods_supported\":[\"plain\",\"S256\"],\"tls_client_certificate_bound_access_tokens\":true,\"revocation_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/revoke\",\"revocation_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"],\"revocation_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"backchannel_logout_supported\":true,\"backchannel_logout_session_supported\":true,\"device_authorization_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/auth/device\",\"backchannel_token_delivery_modes_supported\":[\"poll\",\"ping\"],\"backchannel_authentication_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/ext/ciba/auth\",\"backchannel_authentication_request_signing_alg_values_supported\":[\"PS384\",\"ES384\",\"RS384\",\"ES256\",\"RS256\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"],\"require_pushed_authorization_requests\":false,\"pushed_authorization_request_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/ext/par/request\",\"mtls_endpoint_aliases\":{\"token_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/token\",\"revocation_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/revoke\",\"introspection_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/token/introspect\",\"device_authorization_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/auth/device\",\"registration_endpoint\":\"https://base_url/realms/my_realm/clients-registrations/openid-connect\",\"userinfo_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/userinfo\",\"pushed_authorization_request_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/ext/par/request\",\"backchannel_authentication_endpoint\":\"https://base_url/realms/my_realm/protocol/openid-connect/ext/ciba/auth\"},\"authorization_response_iss_parameter_supported\":true}";
static KEYS: &str = "{\"keys\":[{\"kid\":\"tIyOiDCFY3Kq7gn2QQa-V6uH3uNNVronmb0GPDv_aJ8\",\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"tgHkwkOt3VEL5_xT4PpS_HylBNVs2U-AlQJ7TH6sAVny68vLt021Vh-3wVcTHMkQL-Iy3f9oCpes2xGVBXUt8MhDc6YzIHg5_kCe9THJnprx_atRjHf1y3o5nM5IBXeAZMORpjj2Ltn6iAC05Nj__959UKKwuc-OfHY7HWj--k7EFPtx8accBnpBBgouwQ-g3IcrGU_rgVJy1v3GoSxFPMjmphxUpQCCaMPCX_j6p3yAMTSmO5Md_UWuSL-RlekiIE5KXxIrTZMfeJoh7aWClz48e5P20W5CDD_S4H_sS2Qc_OQdewno8zg1LpDmqBYLqM6f-GdXbGIb_z5OGpOqyw\",\"e\":\"AQAB\",\"x5c\":[\"MIICoTCCAYkCBgGMc1xCGTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlyb21haW5taWMwHhcNMjMxMjE2MTU1OTM1WhcNMzMxMjE2MTYwMTE1WjAUMRIwEAYDVQQDDAlyb21haW5taWMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2AeTCQ63dUQvn/FPg+lL8fKUE1WzZT4CVAntMfqwBWfLry8u3TbVWH7fBVxMcyRAv4jLd/2gKl6zbEZUFdS3wyENzpjMgeDn+QJ71McmemvH9q1GMd/XLejmczkgFd4Bkw5GmOPYu2fqIALTk2P//3n1QorC5z458djsdaP76TsQU+3HxpxwGekEGCi7BD6DchysZT+uBUnLW/cahLEU8yOamHFSlAIJow8Jf+PqnfIAxNKY7kx39Ra5Iv5GV6SIgTkpfEitNkx94miHtpYKXPjx7k/bRbkIMP9Lgf+xLZBz85B17CejzODUukOaoFguozp/4Z1dsYhv/Pk4ak6rLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHYfu4m7idg1DGFUwy8YzB1R5HmHIpZhvOAfOYR7LhPg8966oTf9n5W+qtEEpYYf8rAZ2bZRGZ/FNdXBhjalfx6wX7OaDgFDnwOvu2UP8mcR9Qx5sfHvFSxcpst2Ow4IGyK7+TxatXFgZigMsHtyMk07y/1GnSsJS7QRmD+SmR4H1uSYFUL4EIegKh1IqNiJs/X79B6oTI/GKsq+71g8yIhEXIOW2Ew2FkzyIeY4TrrEsd81bzoYYdGzfnPABv8RRFh9HcX6ny0KEjcKso44KA3+fCzED2FCC2yI/2qBGRFKhr58II0CXtnA57JFi4IsaQwq+meihAD7LhNdo1BkMiI=\"],\"x5t\":\"HbmPdcfmziUZpMFd0jgcjwWbJPk\",\"x5t#S256\":\"HU2FYC7EeuUYPL-54w2xKk7Xd04z2ZsUpQ2MfMAVIps\"},{\"kid\":\"rofNqFX0gSSRJyczVTnED9ht3njkNqBZs18gHy7275g\",\"kty\":\"RSA\",\"alg\":\"RSA-OAEP\",\"use\":\"enc\",\"n\":\"rHenmWwFj8nsSNPMMeJab_y60qHbJDeI-N-VO4L4IEOwlx3w40mTBGgxday8PCxewrCPZhzWNByotOapXqFSN-FJ0Og2ocn8EohzbX2Hexf8ykwDHMque2gVeVAmyhqMVhot9Kok1rLtTDAX7kx3KYwmEF3hQ6ptU7FIDOX_nj9gdTGpM2twpxHwaJjqWn1TzFP6Nbk3YiEvc5oKikeWf5QLHZNoOGFzJ1IGoNEyRdyVIimvdyrA4LWo9RTo7GC02caRrALbV9TTs9_C5fbUSbV7I1NwgQ0ZalM6OgeKH8xb0TfQMO31oVY86OCksCPxaZunqhyHN5Tf-c71nzkGMw\",\"e\":\"AQAB\",\"x5c\":[\"MIICoTCCAYkCBgGMc1xDnTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlyb21haW5taWMwHhcNMjMxMjE2MTU1OTM1WhcNMzMxMjE2MTYwMTE1WjAUMRIwEAYDVQQDDAlyb21haW5taWMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsd6eZbAWPyexI08wx4lpv/LrSodskN4j435U7gvggQ7CXHfDjSZMEaDF1rLw8LF7CsI9mHNY0HKi05qleoVI34UnQ6DahyfwSiHNtfYd7F/zKTAMcyq57aBV5UCbKGoxWGi30qiTWsu1MMBfuTHcpjCYQXeFDqm1TsUgM5f+eP2B1Makza3CnEfBomOpafVPMU/o1uTdiIS9zmgqKR5Z/lAsdk2g4YXMnUgag0TJF3JUiKa93KsDgtaj1FOjsYLTZxpGsAttX1NOz38Ll9tRJtXsjU3CBDRlqUzo6B4ofzFvRN9Aw7fWhVjzo4KSwI/Fpm6eqHIc3lN/5zvWfOQYzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGG9R7sUd7Y9RBrXiOZUEkFRxQJcV6FSgPwQlA/P7sdCHI/eNQevACChL/YEokV0mEekBskbOTxu6mwZAECZhdcfEuPJ13z5zvyH8snWVpA5uDY17FJfoz//pu+5j2+U8kadXsUSlFs3TUd+KVjFIIdsIRcrTDyfEuW42BFHV6XlCA722wCeCAtpBj7+l4FRftrieb56aF8zClJUv3EL8oNsZ8ttArduhOiG3z/EaCL64csBDt4758dC0BbaQy+BLbcPRo3Z4ufZxKb0YFqXzFUPZlTINLl+Q/xwAsom51571gmNGW2I2S3F/AUDVCz2CBcWtSvwU0nbc0tGDlkr4PI=\"],\"x5t\":\"b1_6J5GgO6kvqOHZhKIcdX2ztYk\",\"x5t#S256\":\"EktEMTB6MN_HCbSQELm4M90ThxjbBjnuorie8ORXQxg\"}]}";

fn get_metadata(issuer_url: &str) -> String {
    METADATA.replace("https://base_url", issuer_url)
}

struct OidcEndpointsMock<'a> {
    metadata_endpoint_mock: Mock<'a>,
    keys_endpoint_mock: Mock<'a>,
}

fn build_oidc_mock_server(server: &MockServer) -> OidcEndpointsMock {
    let metadata_endpoint_mock = server.mock(|when, then| {
        when.method(GET)
            .path("/realms/my_realm/.well-known/openid-configuration");
        then.status(200)
            .header("content-type", "application/json; charset=UTF-8")
            .body(get_metadata(server.base_url().clone().as_str()));
    });

    let keys_endpoint_mock = server.mock(|when, then| {
        when.method(GET)
            .path("/realms/my_realm/protocol/openid-connect/certs");
        then.status(200)
            .header("content-type", "application/json; charset=UTF-8")
            .body(KEYS);
    });
    OidcEndpointsMock {
        metadata_endpoint_mock,
        keys_endpoint_mock,
    }
}

#[derive(Debug)]
struct TestResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
}

async fn actix_response_to_test_response(resp: Result<ServiceResponse, Error>) -> TestResponse {
    match resp {
        Ok(http_resp) => {
            let status = http_resp.status().as_u16();
            let headers = http_resp.headers().clone();
            let body = actix_web::test::read_body(http_resp).await;
            TestResponse {
                status,
                headers,
                body,
            }
        }
        Err(err_resp) => {
            let http_resp = err_resp.error_response();
            let status = http_resp.status().as_u16();
            let headers = http_resp.headers().clone();
            let body = actix_web::body::to_bytes(http_resp.into_body())
                .await
                .unwrap();
            TestResponse {
                status,
                headers,
                body,
            }
        }
    }
}

#[actix_web::test]
async fn test_add() {
    let oidc_server = MockServer::start();
    let oidc_endpoints_mock = build_oidc_mock_server(&oidc_server);

    let issuer_url = format!("{}/realms/my_realm", oidc_server.base_url().as_str());
    println!("issuer_url: {}", issuer_url);
    let should_auth =
        |req: &actix_web::dev::ServiceRequest| !req.path().starts_with("/no_auth/hello");
    // using common code.
    let open_id_actix_web = ActixWebOpenId::init(
        "bo".to_string(),
        "bo".to_string(),
        "http://redirect_url.com/auth".to_string(),
        issuer_url,
        should_auth,
        None,
        vec!["bo".to_string()],
    )
    .await;
    oidc_endpoints_mock.metadata_endpoint_mock.assert();
    oidc_endpoints_mock.keys_endpoint_mock.assert();

    let mock_app = mock_auth_api::get_mock_auth_api(&open_id_actix_web).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/is_auth/hello")
        .to_request();
    let resp =
        actix_response_to_test_response(actix_web::test::try_call_service(&mock_app, req).await)
            .await;
    assert_eq!(resp.status, 302);
    resp.headers.get("location").unwrap();
    let query = Url::parse(resp.headers.get("location").unwrap().to_str().unwrap())
        .unwrap()
        .query_pairs();
    let body = actix_web::body::to_bytes(resp.body).await.unwrap();
    println!("body: {:?}", body);
}
