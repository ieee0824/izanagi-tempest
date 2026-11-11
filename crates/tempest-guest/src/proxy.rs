use crate::{config::Config, mapping};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tempest_model::guest::ApiRecord;
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinSet,
};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type HttpBody = BoxBody<Bytes, BoxError>;
pub type HttpClient = Client<HttpConnector, HttpBody>;
pub fn client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build_http()
}
pub fn full(bytes: impl Into<Bytes>) -> HttpBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Default)]
struct Observed {
    hash: Sha256,
    bytes: u64,
    prefix: Vec<u8>,
    complete: bool,
}
impl Observed {
    fn update(&mut self, bytes: &Bytes) {
        self.hash.update(bytes);
        self.bytes += bytes.len() as u64;
        let keep = (mapping::INSPECTION_LIMIT - self.prefix.len()).min(bytes.len());
        self.prefix.extend_from_slice(&bytes[..keep]);
    }
    fn hash(&self) -> String {
        format!("{:x}", self.hash.clone().finalize())
    }
}
struct Log {
    file: Mutex<File>,
    next: AtomicU64,
    failed: AtomicBool,
}
struct Event {
    log: Arc<Log>,
    ts: String,
    method: hyper::Method,
    uri: hyper::Uri,
    headers: hyper::HeaderMap,
    key: Option<String>,
    user_agent: Option<String>,
    request: Arc<Mutex<Observed>>,
    response: Arc<Mutex<Observed>>,
    status: Option<u16>,
    error: Option<String>,
    written: AtomicBool,
}
impl Event {
    fn finish(&self) {
        if self.written.swap(true, Ordering::SeqCst) {
            return;
        }
        let req = self.request.lock().unwrap();
        let resp = self.response.lock().unwrap();
        let mapped = mapping::infer(
            &self.method,
            &self.uri,
            &self.headers,
            &req.prefix,
            req.complete && req.bytes == req.prefix.len() as u64,
        );
        let mut file = self.log.file.lock().unwrap();
        let row = ApiRecord {
            seq: self.log.next.fetch_add(1, Ordering::SeqCst),
            ts: self.ts.clone(),
            method: self.method.to_string(),
            path: self.uri.path().into(),
            service: mapped.service,
            action: mapped.action,
            resource: mapped.resource,
            access_key_id: self.key.clone(),
            user_agent: self.user_agent.clone(),
            status: self.status,
            error_code: if self.status.is_some_and(|s| s >= 400) {
                mapping::error_code(&resp.prefix)
            } else {
                None
            },
            req_bytes: req.bytes,
            req_sha256: req.hash(),
            resp_bytes: resp.bytes,
            resp_sha256: resp.hash(),
            request_complete: req.complete,
            response_complete: resp.complete,
            mapping_diagnostic: mapped.diagnostic,
            transport_error: self.error.clone().or_else(|| {
                (!req.complete || !resp.complete).then(|| "incomplete HTTP stream".into())
            }),
        };
        let result = (|| -> std::io::Result<()> {
            serde_json::to_writer(&mut *file, &row)?;
            file.write_all(b"\n")?;
            file.flush()
        })();
        if result.is_err() {
            self.log.failed.store(true, Ordering::SeqCst);
        }
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        self.finish();
    }
}
struct Measured {
    inner: HttpBody,
    observed: Arc<Mutex<Observed>>,
    event: Option<Arc<Event>>,
}
impl Measured {
    fn wrap(
        inner: HttpBody,
        observed: Arc<Mutex<Observed>>,
        event: Option<Arc<Event>>,
    ) -> HttpBody {
        observed.lock().unwrap().complete = inner.is_end_stream();
        Self {
            inner,
            observed,
            event,
        }
        .boxed()
    }
}
impl Body for Measured {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                {
                    let mut observed = self.observed.lock().unwrap();
                    if let Some(bytes) = frame.data_ref() {
                        observed.update(bytes);
                    }
                    observed.complete = self.inner.is_end_stream();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.observed.lock().unwrap().complete = true;
                if let Some(e) = &self.event {
                    e.finish();
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(event) = &self.event {
                    event.finish();
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
impl Drop for Measured {
    fn drop(&mut self) {
        if let Some(e) = &self.event {
            e.finish();
        }
    }
}

fn strip_hop(headers: &mut hyper::HeaderMap) {
    let names: Vec<String> = headers
        .get("connection")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').map(|s| s.trim().to_owned()).collect())
        .unwrap_or_default();
    for name in names {
        headers.remove(&name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
async fn forward(
    req: Request<Incoming>,
    config: Arc<Config>,
    client: HttpClient,
    log: Arc<Log>,
) -> Result<Response<HttpBody>, Infallible> {
    if log.failed.load(Ordering::SeqCst) {
        return Ok(Response::builder()
            .status(503)
            .body(full("recorder unavailable"))
            .unwrap());
    }
    let (mut parts, body) = req.into_parts();
    let request = Arc::new(Mutex::new(Observed::default()));
    let response = Arc::new(Mutex::new(Observed::default()));
    let key = mapping::access_key(&parts.headers, &parts.uri);
    let user_agent = parts
        .headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.chars().take(1024).collect());
    let mut event = Event {
        log,
        ts: chrono::Utc::now().to_rfc3339(),
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        headers: parts.headers.clone(),
        key,
        user_agent,
        request: request.clone(),
        response: response.clone(),
        status: None,
        error: None,
        written: AtomicBool::new(false),
    };
    // Never use an incoming authority/Host as an upstream destination.
    parts.uri = format!(
        "http://{}{}",
        config.upstream,
        parts.uri.path_and_query().map_or("/", |p| p.as_str())
    )
    .parse()
    .unwrap();
    strip_hop(&mut parts.headers);
    parts
        .headers
        .insert("host", config.upstream.to_string().parse().unwrap());
    let measured = Measured::wrap(
        body.map_err(|e| -> BoxError { Box::new(e) }).boxed(),
        request,
        None,
    );
    let result = tokio::time::timeout(
        Duration::from_secs(config.timeout_seconds),
        client.request(Request::from_parts(parts, measured)),
    )
    .await;
    let (mut parts, body) = match result {
        Ok(Ok(upstream)) => {
            let (parts, body) = upstream.into_parts();
            event.status = Some(parts.status.as_u16());
            (parts, body.map_err(|e| -> BoxError { Box::new(e) }).boxed())
        }
        _ => {
            event.status = Some(502);
            event.error = Some("upstream connection, timeout or request stream failure".into());
            Response::builder()
                .status(502)
                .body(full("upstream unavailable"))
                .unwrap()
                .into_parts()
        }
    };
    strip_hop(&mut parts.headers);
    let event = Arc::new(event);
    Ok(Response::from_parts(
        parts,
        Measured::wrap(body, response, Some(event)),
    ))
}

/// Internal lws-uid child. Control and capture remain in the root supervisor.
pub async fn serve(config: Config) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .context("bind recorder loopback listener")?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.evidence_dir.join("api.jsonl"))
        .context("create API evidence")?;
    let log = Arc::new(Log {
        file: Mutex::new(file),
        next: AtomicU64::new(1),
        failed: AtomicBool::new(false),
    });
    let timeout = config.timeout_seconds;
    let config = Arc::new(config);
    let client = client();
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let (closing, _) = watch::channel(false);
    let mut tasks = JoinSet::new();
    println!("{{\"ready\":true}}");
    std::io::stdout().flush()?;
    loop {
        tokio::select! {
            _=terminate.recv()=>break,
            _=interrupt.recv()=>break,
            accepted=listener.accept()=>{
                let (socket,_)=accepted?;
                if tasks.len()>=256 {drop(socket);continue;}
                let config=config.clone();let client=client.clone();let log=log.clone();let mut closing=closing.subscribe();
                tasks.spawn(async move {
                    let connection=hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(socket),service_fn(move |req|forward(req,config.clone(),client.clone(),log.clone())));
                    tokio::pin!(connection);
                    tokio::select! {
                        _=&mut connection=>{},
                        _=closing.changed()=>{connection.as_mut().graceful_shutdown();let _=connection.await;}
                    }
                });
            },
            Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
        }
    }
    drop(listener);
    let _ = closing.send(true);
    let drained = tokio::time::timeout(Duration::from_secs(timeout), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();
    if !drained {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    log.file.lock().unwrap().sync_all()?;
    ensure!(
        drained && !log.failed.load(Ordering::SeqCst),
        "recorder drain or evidence write failed"
    );
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseSummary {
    pub status: u16,
    pub error_code: Option<String>,
    pub body: Vec<u8>,
    pub complete: bool,
}
/// Trusted local control/probe client: drains and hashes on the proxy path, only
/// a bounded response prefix is retained here for health/admin classification.
pub async fn request(
    client: &HttpClient,
    request: Request<HttpBody>,
    timeout: u64,
) -> Result<ResponseSummary> {
    tokio::time::timeout(Duration::from_secs(timeout), async {
        let response = client
            .request(request)
            .await
            .context("local HTTP request failed")?;
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut prefix = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.context("local HTTP response incomplete")?;
            if let Some(data) = frame.data_ref() {
                let keep = (mapping::INSPECTION_LIMIT - prefix.len()).min(data.len());
                prefix.extend_from_slice(&data[..keep]);
            }
        }
        let code = if status >= 400 {
            mapping::error_code(&prefix)
        } else {
            None
        };
        Ok(ResponseSummary {
            status,
            error_code: code,
            body: prefix,
            complete: true,
        })
    })
    .await
    .context("local HTTP request timeout")?
}
