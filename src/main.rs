use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, Request, StatusCode},
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Display;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};


static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").unwrap_or("my_secret".to_string());
    Keys::new(secret.as_bytes())
});

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_jwt=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = app();

    let ip = "127.0.0.1:3456";
    axum::Server::bind(&ip.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    tracing::debug!("listening on {}", ip);
}

fn app() -> Router {
    Router::new()
        .route("/protected", get(protected))
        .route_layer(from_fn(mw_require_auth))
        .route_layer(from_fn(mw_ctx_resolver))
        .route("/authorize", post(authorize))
}

/// Validated route
async fn protected(ctx: Ctx) -> Result<Json<Value>, AuthError> {
    Ok( Json( json!({ "message": format!("Welcome {}", ctx.claims) })))
}

/// Make a dummy token
fn make_token() -> Result<String, AuthError> {
    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: 2_000_000_000,
    };
    encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)
}


/// Handler to generate a token
async fn authorize(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    tracing::debug!("Authenticating: {:?}", payload);
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    if payload.client_id != "foo" || payload.client_secret != "bar" {
        return Err(AuthError::WrongCredentials);
    }

    let token = make_token()?;

    Ok(Json(AuthBody::new(token)))
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}: Company: {}", self.sub, self.company)
    }
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "bearer".to_string(),
        }
    }
}

/// Midleware to parse token from header, put in ctx, and insert into requst extensions. 
/// Should never return an error. Should context extraction fail, the error will be put in
/// the request extensions. The failure to extract the context will be handled by the
/// require auth middleware.
pub async fn mw_ctx_resolver<B>(
    mut req: Request<B>,
    next: Next<B>,
    ) -> Result<Response, AuthError> {
    tracing::debug!("mw_ctx_resolver");
    let auth_header: Option<&str> = req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());
    tracing::debug!("mw_ctx_resolver auth_header: {:?}", auth_header);

    let ctx = auth_header
        .and_then(|header| header.strip_prefix("Bearer "))
        .and_then(|token| decode::<Claims>(token, &KEYS.decoding, &Validation::default()).ok())
        .map(|data| Ctx::new(data.claims));

    // TODO check claims against db?
    req.extensions_mut().insert(ctx.ok_or(AuthError::InvalidToken));

    tracing::debug!("mw_ctx_resolver finished");

    Ok(next.run(req).await)
}

/// Use this middleware if auth is required. If mw_ctx_resolver did not insert 
/// a context in the request extensions, this middleware will return an error.
pub async fn mw_require_auth<B>(
    ctx: Result<Ctx, AuthError>,
    req: Request<B>,
    next: Next<B>,
    ) -> Result<Response, AuthError> {
    tracing::debug!("mw_require_auth");
    ctx?;
    Ok(next.run(req).await)
}

// extractor for Ctx
#[async_trait]
impl<S> FromRequestParts<S> for Ctx
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        tracing::debug!("Ctx extractor");
        parts
            .extensions
            .get::<Result<Ctx, AuthError>>()
            .ok_or(AuthError::MissingCredentials)?
            .clone()
    }
}

/// Extractor the produces a Claims struct from a header.
// #[async_trait]
// impl<S> FromRequestParts<S> for Claims
// where
//     S: Send + Sync,
// {
//     type Rejection = AuthError;

//     async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
//         // Extract the token from the authorization header
//         let TypedHeader(Authorization(bearer)) = parts
//             .extract::<TypedHeader<Authorization<Bearer>>>()
//             .await
//             .map_err(|_| AuthError::InvalidToken)?;

//         tracing::debug!("Bearer token: {:?}", bearer);

//         // Decode the user data
//         let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
//             .map_err(|_| AuthError::InvalidToken)?;

//         Ok(token_data.claims)
//     }
// }

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug, Clone)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        let body = Json(json!({ "error": error_message }));
        (status, body).into_response()
    }
}

/// context struct will be parsed from header by middleware
#[derive(Debug, Clone)]
pub struct Ctx {
    claims: Claims,
}

impl Ctx {
    pub fn new(claims: Claims) -> Self {
        Self { claims }
    }

    pub fn claims(&self) -> &Claims {
        &self.claims
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_authorize() {
        let app = Router::new().route("/authorize", post(authorize));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/authorize")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"client_id": "foo", "client_secret": "bar"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Print the response
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let token = body.get("access_token").unwrap().as_str().unwrap();
        println!("Token: {}", token);
        assert_eq!(token.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_protected_no_auth_hdr() {
        let app = Router::new()
            .route("/protected", get(protected))
            .route_layer(from_fn(mw_require_auth))
            .route_layer(from_fn(mw_ctx_resolver));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/protected")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_bad_auth_hdr() {
        let app = Router::new()
            .route("/protected", get(protected))
            .route_layer(from_fn(mw_require_auth))
            .route_layer(from_fn(mw_ctx_resolver));

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/protected")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header(http::header::AUTHORIZATION, "Bearer foo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_good_auth_hdr() {
        let app = Router::new()
            .route("/protected", get(protected))
            .route_layer(from_fn(mw_require_auth))
            .route_layer(from_fn(mw_ctx_resolver));

        let token = make_token().unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/protected")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header(http::header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
