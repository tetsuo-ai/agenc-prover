use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{serve, Router};
use serde::{Deserialize, Serialize};
use tracing::info;

const FIELD_LEN: usize = 32;

#[derive(Debug, Deserialize)]
struct ProveRequest {
    task_pda: Vec<u8>,
    agent_authority: Vec<u8>,
    constraint_hash: Vec<u8>,
    output_commitment: Vec<u8>,
    binding: Vec<u8>,
    nullifier: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ProveResponse {
    seal_bytes: Vec<u8>,
    journal: Vec<u8>,
    image_id: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_implemented(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

fn app() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/prove", post(prove))
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "agenc-prover-server",
    })
}

async fn prove(Json(request): Json<ProveRequest>) -> Result<Json<ProveResponse>, AppError> {
    validate_request(&request)?;
    Err(AppError::not_implemented(
        "proof generation is not wired in yet",
    ))
}

fn validate_request(request: &ProveRequest) -> Result<(), AppError> {
    validate_len("task_pda", &request.task_pda)?;
    validate_len("agent_authority", &request.agent_authority)?;
    validate_len("constraint_hash", &request.constraint_hash)?;
    validate_len("output_commitment", &request.output_commitment)?;
    validate_len("binding", &request.binding)?;
    validate_len("nullifier", &request.nullifier)?;
    Ok(())
}

fn validate_len(name: &str, bytes: &[u8]) -> Result<(), AppError> {
    if bytes.len() != FIELD_LEN {
        return Err(AppError::bad_request(format!(
            "{name} must be exactly {FIELD_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn bind_addr() -> Result<SocketAddr, String> {
    let host = env::var("PROVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PROVER_PORT").unwrap_or_else(|_| "8787".to_string());

    let ip = host
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid PROVER_HOST {host}: {err}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|err| format!("invalid PROVER_PORT {port}: {err}"))?;

    Ok(SocketAddr::new(ip, port))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agenc_prover_server=info,tower_http=info".into()),
        )
        .init();

    let addr = bind_addr().unwrap_or_else(|err| {
        eprintln!("{err}");
        SocketAddr::from((Ipv4Addr::LOCALHOST, 8787))
    });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| panic!("failed to bind {addr}: {err}"));
    info!(
        "agenc-prover-server listening on {}",
        listener.local_addr().unwrap()
    );
    serve(listener, app())
        .await
        .unwrap_or_else(|err| panic!("server failed: {err}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn valid_request_json() -> String {
        serde_json::json!({
            "task_pda": vec![1; FIELD_LEN],
            "agent_authority": vec![2; FIELD_LEN],
            "constraint_hash": vec![3; FIELD_LEN],
            "output_commitment": vec![4; FIELD_LEN],
            "binding": vec![5; FIELD_LEN],
            "nullifier": vec![6; FIELD_LEN]
        })
        .to_string()
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn prove_rejects_invalid_lengths() {
        let payload = serde_json::json!({
            "task_pda": vec![1; 31],
            "agent_authority": vec![2; FIELD_LEN],
            "constraint_hash": vec![3; FIELD_LEN],
            "output_commitment": vec![4; FIELD_LEN],
            "binding": vec![5; FIELD_LEN],
            "nullifier": vec![6; FIELD_LEN]
        })
        .to_string();

        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prove_returns_not_implemented_for_valid_input() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .body(Body::from(valid_request_json()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
