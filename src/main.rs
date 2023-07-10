use axum::{
    async_trait,
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router, TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::Display;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Quick instructions
//
// - get an authorization token:
//
// curl -s -w '\n' -H 'Content-Type: application/json' \
//     -d '{"client_id":"foo","client_secret":"bar"}' \
//     http://localhost:3456/authorize
//
// - visit the protected area using the authorized token
//
// curl -s  -w '\n'  -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjIwMDAwMDAwMDB9.uR_4i-0-xf5N3ygVI9AT6XEelatzbuVRFnpBLKao6rs' \
//     http://localhost:3456/protected
//
// - try to visit the protected area using an invalid token
//
// curl -s  -w '\n' -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer blahblahblah' \
//     http://localhost:3456/protected
//
// - try to visit the protected area using no token
//
// curl -s  -w '\n' -H 'Content-Type: application/json' http://localhost:3456/protected

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

    let app = Router::new()
        .route("/protected", get(protected))
        .route("/authorize", post(authorize));

    let ip = "127.0.0.1:3456";
    axum::Server::bind(&ip.parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    tracing::debug!("listening on {}", ip);
}

/// Validated route
async fn protected(claims: Claims) -> Result<String, AuthError> {
    Ok(format!(
        "Welcome to protected area: \nYour data:\n{}",
        claims
    ))
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
    let claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned(),
        exp: 2_000_000_000,
    };
    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

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

/// Extractor the produces a Claims struct from a header.
#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        tracing::debug!("Bearer token: {:?}", bearer);

        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
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

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
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

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}
