use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Json, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{serve, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

mod prover;

const FIELD_LEN: usize = 32;
const OUTPUT_COUNT: usize = 4;
const PROVER_HOST_ENV: &str = "PROVER_HOST";
const PROVER_PORT_ENV: &str = "PROVER_PORT";
const PROVER_API_KEY_ENV: &str = "PROVER_API_KEY";
const PROVER_LOCAL_DEV_MODE_ENV: &str = "PROVER_LOCAL_DEV_MODE";
const PROVER_MAX_IN_FLIGHT_ENV: &str = "PROVER_MAX_IN_FLIGHT";
const PROVER_REQUEST_TIMEOUT_SECS_ENV: &str = "PROVER_REQUEST_TIMEOUT_SECS";
const PROVER_RATE_LIMIT_MAX_REQUESTS_ENV: &str = "PROVER_RATE_LIMIT_MAX_REQUESTS";
const PROVER_RATE_LIMIT_WINDOW_SECS_ENV: &str = "PROVER_RATE_LIMIT_WINDOW_SECS";
const DEFAULT_PROVER_MAX_IN_FLIGHT: usize = 1;
const DEFAULT_PROVER_REQUEST_TIMEOUT_SECS: u64 = 900;
const DEFAULT_PROVER_RATE_LIMIT_MAX_REQUESTS: usize = 10;
const DEFAULT_PROVER_RATE_LIMIT_WINDOW_SECS: u64 = 60;

type ProveFn =
    dyn Fn(prover::ProveRequest) -> Result<prover::ProveResponse, prover::ProveError> + Send + Sync;

#[derive(Clone)]
struct AppState {
    prove_auth: ProveAuth,
    prove_runtime: ProveRuntime,
}

#[derive(Clone)]
enum ProveAuth {
    Disabled,
    ApiKey(String),
}

#[derive(Clone)]
struct ProveRuntime {
    prove_fn: Arc<ProveFn>,
    in_flight: Arc<Semaphore>,
    max_in_flight: usize,
    request_timeout: Duration,
    retry_after_seconds: u64,
    rate_limiter: Arc<RateLimiter>,
}

#[derive(Clone, Copy)]
struct ExecutionPolicy {
    max_in_flight: usize,
    request_timeout: Duration,
    rate_limit: RateLimitPolicy,
}

#[derive(Clone, Copy)]
struct RateLimitPolicy {
    max_requests: usize,
    window: Duration,
}

#[derive(Clone, Copy)]
enum RateLimitBucket {
    LocalDev,
    Protected,
}

struct RateLimiter {
    policy: RateLimitPolicy,
    local_dev: Mutex<FixedWindowState>,
    protected: Mutex<FixedWindowState>,
}

struct FixedWindowState {
    started_at: Instant,
    request_count: usize,
}

struct RuntimeConfig {
    addr: SocketAddr,
    prove_auth: ProveAuth,
    execution_policy: ExecutionPolicy,
}

#[derive(Debug, Deserialize)]
struct ProveRequest {
    task_pda: Vec<u8>,
    agent_authority: Vec<u8>,
    constraint_hash: Vec<u8>,
    output_commitment: Vec<u8>,
    binding: Vec<u8>,
    nullifier: Vec<u8>,
    output: Vec<Vec<u8>>,
    salt: Vec<u8>,
    agent_secret: Vec<u8>,
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
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after_seconds: Option<u64>,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
            retry_after_seconds: None,
        }
    }

    fn overloaded(message: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "prove_overloaded",
            message: message.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }

    fn too_many_requests(message: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "prove_rate_limited",
            message: message.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }

    fn timeout(message: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: "prove_timeout",
            message: message.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorResponse {
                error: self.message,
                code: self.code,
                retry_after_seconds: self.retry_after_seconds,
            }),
        )
            .into_response();

        if let Some(retry_after_seconds) = self.retry_after_seconds {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after_seconds.to_string()).unwrap(),
            );
        }

        response
    }
}

impl ProveRequest {
    fn try_into_fixed(self) -> Result<prover::ProveRequest, AppError> {
        let output = self.output.try_into_fixed_output()?;

        Ok(prover::ProveRequest {
            task_pda: vec_to_field("task_pda", self.task_pda)?,
            agent_authority: vec_to_field("agent_authority", self.agent_authority)?,
            constraint_hash: vec_to_field("constraint_hash", self.constraint_hash)?,
            output_commitment: vec_to_field("output_commitment", self.output_commitment)?,
            binding: vec_to_field("binding", self.binding)?,
            nullifier: vec_to_field("nullifier", self.nullifier)?,
            output,
            salt: vec_to_field("salt", self.salt)?,
            agent_secret: vec_to_field("agent_secret", self.agent_secret)?,
        })
    }
}

trait OutputFieldsExt {
    fn try_into_fixed_output(self) -> Result<[[u8; FIELD_LEN]; OUTPUT_COUNT], AppError>;
}

impl OutputFieldsExt for Vec<Vec<u8>> {
    fn try_into_fixed_output(self) -> Result<[[u8; FIELD_LEN]; OUTPUT_COUNT], AppError> {
        let outputs: [Vec<u8>; OUTPUT_COUNT] =
            self.try_into().map_err(|values: Vec<Vec<u8>>| {
                AppError::bad_request(format!(
                    "output must contain exactly {OUTPUT_COUNT} field elements, got {}",
                    values.len()
                ))
            })?;

        Ok([
            vec_to_field("output[0]", outputs[0].clone())?,
            vec_to_field("output[1]", outputs[1].clone())?,
            vec_to_field("output[2]", outputs[2].clone())?,
            vec_to_field("output[3]", outputs[3].clone())?,
        ])
    }
}

fn vec_to_field(name: &str, bytes: Vec<u8>) -> Result<[u8; FIELD_LEN], AppError> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        AppError::bad_request(format!(
            "{name} must be exactly {FIELD_LEN} bytes, got {}",
            bytes.len()
        ))
    })
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/prove", post(prove))
        .with_state(state)
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "agenc-prover-server",
    })
}

async fn prove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, AppError> {
    let rate_limit_bucket = state.prove_auth.authorize(&headers)?;
    state.prove_runtime.check_rate_limit(rate_limit_bucket)?;

    let fixed = request.try_into_fixed()?;
    let permit = state.prove_runtime.try_acquire()?;
    let prove_fn = state.prove_runtime.prove_fn.clone();
    let request_timeout = state.prove_runtime.request_timeout;
    let retry_after_seconds = state.prove_runtime.retry_after_seconds;
    let handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        prove_fn(fixed)
    });

    let response = match tokio::time::timeout(request_timeout, handle).await {
        Ok(joined) => joined
            .map_err(|err| AppError::internal(format!("prover task join failed: {err}")))?
            .map_err(|err| match err {
                prover::ProveError::InvalidRequest(message) => AppError::bad_request(message),
                other => AppError::internal(other.to_string()),
            })?,
        Err(_) => {
            warn!(
                request_timeout_secs = request_timeout.as_secs(),
                "proof request timed out while proving continued in background"
            );
            return Err(AppError::timeout(
                format!(
                    "proof request exceeded {} seconds; retry after the current in-flight work settles",
                    request_timeout.as_secs()
                ),
                retry_after_seconds,
            ));
        }
    };

    Ok(Json(ProveResponse {
        seal_bytes: response.seal_bytes,
        journal: response.journal,
        image_id: response.image_id.to_vec(),
    }))
}

fn bind_addr() -> Result<SocketAddr, String> {
    let host = env::var(PROVER_HOST_ENV).unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var(PROVER_PORT_ENV).unwrap_or_else(|_| "8787".to_string());

    let ip = host
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid {PROVER_HOST_ENV} {host}: {err}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|err| format!("invalid {PROVER_PORT_ENV} {port}: {err}"))?;

    Ok(SocketAddr::new(ip, port))
}

fn runtime_config() -> Result<RuntimeConfig, String> {
    let addr = bind_addr()?;
    let local_dev_mode = parse_env_bool(PROVER_LOCAL_DEV_MODE_ENV)?;
    let api_key = env::var(PROVER_API_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let prove_auth = resolve_prove_auth(addr.ip(), local_dev_mode, api_key)?;
    let execution_policy = execution_policy()?;

    Ok(RuntimeConfig {
        addr,
        prove_auth,
        execution_policy,
    })
}

fn parse_env_bool(name: &str) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(format!("invalid {name} value {other:?}; use true/false")),
        },
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn resolve_prove_auth(
    bind_ip: IpAddr,
    local_dev_mode: bool,
    api_key: Option<String>,
) -> Result<ProveAuth, String> {
    if local_dev_mode {
        if !bind_ip.is_loopback() {
            return Err(format!(
                "{PROVER_LOCAL_DEV_MODE_ENV}=true is only allowed when {PROVER_HOST_ENV} is loopback"
            ));
        }

        return Ok(ProveAuth::Disabled);
    }

    let api_key = api_key.ok_or_else(|| {
        format!(
            "{PROVER_API_KEY_ENV} is required unless {PROVER_LOCAL_DEV_MODE_ENV}=true on loopback"
        )
    })?;

    Ok(ProveAuth::ApiKey(api_key))
}

fn execution_policy() -> Result<ExecutionPolicy, String> {
    let max_in_flight =
        parse_nonzero_usize_env(PROVER_MAX_IN_FLIGHT_ENV, DEFAULT_PROVER_MAX_IN_FLIGHT)?;
    let request_timeout_secs = parse_nonzero_u64_env(
        PROVER_REQUEST_TIMEOUT_SECS_ENV,
        DEFAULT_PROVER_REQUEST_TIMEOUT_SECS,
    )?;
    let rate_limit_max_requests = parse_nonzero_usize_env(
        PROVER_RATE_LIMIT_MAX_REQUESTS_ENV,
        DEFAULT_PROVER_RATE_LIMIT_MAX_REQUESTS,
    )?;
    let rate_limit_window_secs = parse_nonzero_u64_env(
        PROVER_RATE_LIMIT_WINDOW_SECS_ENV,
        DEFAULT_PROVER_RATE_LIMIT_WINDOW_SECS,
    )?;

    Ok(resolve_execution_policy(
        max_in_flight,
        request_timeout_secs,
        rate_limit_max_requests,
        rate_limit_window_secs,
    ))
}

fn parse_nonzero_usize_env(name: &str, default: usize) -> Result<usize, String> {
    match env::var(name) {
        Ok(value) => {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|err| format!("invalid {name} value {value:?}: {err}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero"));
            }
            Ok(parsed)
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn parse_nonzero_u64_env(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) => {
            let parsed = value
                .trim()
                .parse::<u64>()
                .map_err(|err| format!("invalid {name} value {value:?}: {err}"))?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero"));
            }
            Ok(parsed)
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn resolve_execution_policy(
    max_in_flight: usize,
    request_timeout_secs: u64,
    rate_limit_max_requests: usize,
    rate_limit_window_secs: u64,
) -> ExecutionPolicy {
    ExecutionPolicy {
        max_in_flight,
        request_timeout: Duration::from_secs(request_timeout_secs),
        rate_limit: RateLimitPolicy {
            max_requests: rate_limit_max_requests,
            window: Duration::from_secs(rate_limit_window_secs),
        },
    }
}

impl ExecutionPolicy {
    fn retry_after_seconds(&self) -> u64 {
        self.request_timeout.as_secs().max(1)
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }

    let token = token.trim();
    if token.is_empty() {
        return None;
    }

    Some(token)
}

impl ProveAuth {
    fn authorize(&self, headers: &HeaderMap) -> Result<RateLimitBucket, AppError> {
        match self {
            ProveAuth::Disabled => Ok(RateLimitBucket::LocalDev),
            ProveAuth::ApiKey(expected) => match extract_bearer_token(headers) {
                Some(candidate) if candidate == expected => Ok(RateLimitBucket::Protected),
                Some(_) => Err(AppError::unauthorized("invalid API key")),
                None => Err(AppError::unauthorized("missing bearer token for /prove")),
            },
        }
    }
}

impl ProveRuntime {
    fn new(execution_policy: ExecutionPolicy) -> Self {
        Self {
            prove_fn: Arc::new(|request| prover::generate_proof(&request)),
            in_flight: Arc::new(Semaphore::new(execution_policy.max_in_flight)),
            max_in_flight: execution_policy.max_in_flight,
            request_timeout: execution_policy.request_timeout,
            retry_after_seconds: execution_policy.retry_after_seconds(),
            rate_limiter: Arc::new(RateLimiter::new(execution_policy.rate_limit)),
        }
    }

    fn check_rate_limit(&self, bucket: RateLimitBucket) -> Result<(), AppError> {
        self.rate_limiter.check(bucket)
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, AppError> {
        self.in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                AppError::overloaded(
                    format!(
                        "prover is saturated: max {} in-flight proof request(s); queue policy is fail-fast",
                        self.max_in_flight
                    ),
                    self.retry_after_seconds,
                )
            })
    }
}

impl RateLimitPolicy {
    fn retry_after_seconds(&self, elapsed: Duration) -> u64 {
        self.window.saturating_sub(elapsed).as_secs().max(1)
    }
}

impl RateLimiter {
    fn new(policy: RateLimitPolicy) -> Self {
        Self {
            policy,
            local_dev: Mutex::new(FixedWindowState::new()),
            protected: Mutex::new(FixedWindowState::new()),
        }
    }

    fn check(&self, bucket: RateLimitBucket) -> Result<(), AppError> {
        let state = match bucket {
            RateLimitBucket::LocalDev => &self.local_dev,
            RateLimitBucket::Protected => &self.protected,
        };
        let mut state = state
            .lock()
            .map_err(|_| AppError::internal("rate limiter lock poisoned"))?;
        let elapsed = state.started_at.elapsed();

        if elapsed >= self.policy.window {
            state.started_at = Instant::now();
            state.request_count = 0;
        }

        if state.request_count >= self.policy.max_requests {
            return Err(AppError::too_many_requests(
                format!(
                    "proof request rate limit exceeded: max {} request(s) per {} second window",
                    self.policy.max_requests,
                    self.policy.window.as_secs()
                ),
                self.policy.retry_after_seconds(elapsed),
            ));
        }

        state.request_count += 1;
        Ok(())
    }
}

impl FixedWindowState {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            request_count: 0,
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agenc_prover_server=info,tower_http=info".into()),
        )
        .init();

    if matches!(env::args().nth(1).as_deref(), Some("image-id")) {
        println!("{}", prover::render_image_id(prover::image_id()));
        return;
    }

    let runtime = runtime_config().unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let addr = runtime.addr;
    let state = AppState {
        prove_auth: runtime.prove_auth,
        prove_runtime: ProveRuntime::new(runtime.execution_policy),
    };

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("failed to bind {addr}: {err}");
            std::process::exit(1);
        });
    info!(
        "agenc-prover-server listening on {}",
        listener.local_addr().unwrap()
    );
    match &state.prove_auth {
        ProveAuth::Disabled => info!(
            "{PROVER_LOCAL_DEV_MODE_ENV}=true; /prove is running without auth on loopback"
        ),
        ProveAuth::ApiKey(_) => info!(
            "/prove requires Authorization: Bearer <token>; configure {PROVER_API_KEY_ENV} for clients"
        ),
    }
    info!(
        max_in_flight = runtime.execution_policy.max_in_flight,
        request_timeout_secs = runtime.execution_policy.request_timeout.as_secs(),
        rate_limit_max_requests = runtime.execution_policy.rate_limit.max_requests,
        rate_limit_window_secs = runtime.execution_policy.rate_limit.window.as_secs(),
        queue_policy = "fail-fast",
        "active /prove execution limits"
    );
    serve(listener, app(state))
        .await
        .unwrap_or_else(|err| panic!("server failed: {err}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_zkvm_guest::{
        compute_binding, compute_constraint_hash, compute_nullifier_from_agent_secret,
        compute_output_commitment,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn local_dev_app() -> Router {
        app(AppState {
            prove_auth: ProveAuth::Disabled,
            prove_runtime: ProveRuntime::new(resolve_execution_policy(1, 900, 10, 60)),
        })
    }

    fn protected_app() -> Router {
        app(AppState {
            prove_auth: ProveAuth::ApiKey("test-token".to_string()),
            prove_runtime: ProveRuntime::new(resolve_execution_policy(1, 900, 10, 60)),
        })
    }

    fn test_rate_limiter(max_requests: usize, window_secs: u64) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(RateLimitPolicy {
            max_requests,
            window: Duration::from_secs(window_secs),
        }))
    }

    fn field_from_u32(value: u32) -> Vec<u8> {
        let mut out = vec![0_u8; FIELD_LEN];
        out[28..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn valid_request_json() -> String {
        let mut task_pda = vec![0_u8; FIELD_LEN];
        task_pda[31] = 0x2a;
        let agent_authority = (1u8..=32u8).collect::<Vec<_>>();
        let output = vec![
            field_from_u32(1),
            field_from_u32(2),
            field_from_u32(3),
            field_from_u32(4),
        ];
        let output_fields = [
            vec_to_field("output[0]", output[0].clone()).unwrap(),
            vec_to_field("output[1]", output[1].clone()).unwrap(),
            vec_to_field("output[2]", output[2].clone()).unwrap(),
            vec_to_field("output[3]", output[3].clone()).unwrap(),
        ];
        let salt = field_from_u32(12345);
        let agent_secret = field_from_u32(67890);
        let constraint_hash = compute_constraint_hash(&output_fields);
        let output_commitment =
            compute_output_commitment(&output_fields, &vec_to_field("salt", salt.clone()).unwrap());
        let binding = compute_binding(
            &vec_to_field("task_pda", task_pda.clone()).unwrap(),
            &vec_to_field("agent_authority", agent_authority.clone()).unwrap(),
            &output_commitment,
        );
        let nullifier = compute_nullifier_from_agent_secret(
            &constraint_hash,
            &output_commitment,
            &vec_to_field("agent_secret", agent_secret.clone()).unwrap(),
        );

        serde_json::json!({
            "task_pda": task_pda,
            "agent_authority": agent_authority,
            "constraint_hash": constraint_hash,
            "output_commitment": output_commitment,
            "binding": binding,
            "nullifier": nullifier,
            "output": output,
            "salt": salt,
            "agent_secret": agent_secret
        })
        .to_string()
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = local_dev_app()
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
            "nullifier": vec![6; FIELD_LEN],
            "output": vec![vec![7; FIELD_LEN]; OUTPUT_COUNT],
            "salt": vec![8; FIELD_LEN],
            "agent_secret": vec![9; FIELD_LEN]
        })
        .to_string();

        let response = local_dev_app()
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
    async fn prove_rejects_wrong_output_count() {
        let payload = serde_json::json!({
            "task_pda": vec![1; FIELD_LEN],
            "agent_authority": vec![2; FIELD_LEN],
            "constraint_hash": vec![3; FIELD_LEN],
            "output_commitment": vec![4; FIELD_LEN],
            "binding": vec![5; FIELD_LEN],
            "nullifier": vec![6; FIELD_LEN],
            "output": vec![vec![7; FIELD_LEN]; 3],
            "salt": vec![8; FIELD_LEN],
            "agent_secret": vec![9; FIELD_LEN]
        })
        .to_string();

        let response = local_dev_app()
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
    async fn prove_rejects_invalid_semantics_as_bad_request() {
        let mut payload: serde_json::Value =
            serde_json::from_str(&valid_request_json()).expect("valid request json");
        payload["binding"] = serde_json::json!(vec![0; FIELD_LEN]);

        let response = local_dev_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn prove_rejects_missing_bearer_token_when_protected() {
        let response = protected_app()
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

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn prove_rejects_invalid_bearer_token_when_protected() {
        let response = protected_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer wrong-token")
                    .body(Body::from(valid_request_json()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn prove_accepts_valid_bearer_token_when_protected() {
        let response = protected_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(valid_request_json()))
                    .unwrap(),
            )
            .await
            .unwrap();

        #[cfg(not(feature = "production-prover"))]
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn prove_fails_fast_when_saturated() {
        let app = app(AppState {
            prove_auth: ProveAuth::Disabled,
            prove_runtime: ProveRuntime {
                prove_fn: Arc::new(|_| unreachable!("saturated requests must not enter prover")),
                in_flight: Arc::new(Semaphore::new(0)),
                max_in_flight: 1,
                request_timeout: Duration::from_secs(5),
                retry_after_seconds: 5,
                rate_limiter: test_rate_limiter(10, 60),
            },
        });

        let response = app
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

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "5");
    }

    #[tokio::test]
    async fn prove_returns_gateway_timeout_when_request_expires() {
        let app = app(AppState {
            prove_auth: ProveAuth::Disabled,
            prove_runtime: ProveRuntime {
                prove_fn: Arc::new(|_| {
                    std::thread::sleep(Duration::from_millis(50));
                    Err(prover::ProveError::ProverFailed("slow proof".into()))
                }),
                in_flight: Arc::new(Semaphore::new(1)),
                max_in_flight: 1,
                request_timeout: Duration::from_millis(10),
                retry_after_seconds: 1,
                rate_limiter: test_rate_limiter(10, 60),
            },
        });

        let response = app
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

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[tokio::test]
    async fn prove_rate_limits_authenticated_requests() {
        let app = app(AppState {
            prove_auth: ProveAuth::ApiKey("test-token".to_string()),
            prove_runtime: ProveRuntime {
                prove_fn: Arc::new(|_| Err(prover::ProveError::ProverFailed("boom".into()))),
                in_flight: Arc::new(Semaphore::new(1)),
                max_in_flight: 1,
                request_timeout: Duration::from_secs(5),
                retry_after_seconds: 5,
                rate_limiter: test_rate_limiter(1, 1),
            },
        });

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(valid_request_json()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/prove")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(valid_request_json()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn resolve_prove_auth_allows_explicit_loopback_local_dev_mode() {
        let auth = resolve_prove_auth(IpAddr::V4(Ipv4Addr::LOCALHOST), true, None).unwrap();

        assert!(matches!(auth, ProveAuth::Disabled));
    }

    #[test]
    fn resolve_prove_auth_requires_api_key_outside_local_dev_mode() {
        let error = match resolve_prove_auth(IpAddr::V4(Ipv4Addr::LOCALHOST), false, None) {
            Err(error) => error,
            Ok(_) => panic!("expected missing API key to fail"),
        };

        assert!(error.contains(PROVER_API_KEY_ENV));
    }

    #[test]
    fn resolve_prove_auth_rejects_local_dev_mode_on_public_bind() {
        let error = match resolve_prove_auth(IpAddr::V4(Ipv4Addr::UNSPECIFIED), true, None) {
            Err(error) => error,
            Ok(_) => panic!("expected non-loopback local dev mode to fail"),
        };

        assert!(error.contains(PROVER_LOCAL_DEV_MODE_ENV));
    }

    #[test]
    fn resolve_execution_policy_uses_expected_values() {
        let policy = resolve_execution_policy(2, 600, 10, 60);

        assert_eq!(policy.max_in_flight, 2);
        assert_eq!(policy.request_timeout, Duration::from_secs(600));
        assert_eq!(policy.retry_after_seconds(), 600);
        assert_eq!(policy.rate_limit.max_requests, 10);
        assert_eq!(policy.rate_limit.window, Duration::from_secs(60));
    }
}
