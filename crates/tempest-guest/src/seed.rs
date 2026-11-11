use crate::{
    config::Config,
    proxy::{self, HttpBody, HttpClient, ResponseSummary},
};
use anyhow::{Context, Result, bail, ensure};
use hyper::{Method, Request};
use rand::RngCore;
use serde_json::Value;
use std::os::unix::process::ExitStatusExt;
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tempest_model::{
    ScenarioInput,
    capability::{self, Support},
    guest::{AccessKeys, ProbeOutcome, ProbeRequest, ProbeResult, SeedBundle},
    scenario::{Budget, Deviation},
};
use tokio::process::{Child, Command};

const S3_PATH: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'/');

pub fn random_secret() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Classify observed HTTP only; an unknown credential is never policy evidence.
pub fn classify(
    status: u16,
    code: Option<&str>,
    complete: bool,
    credential_known: bool,
) -> ProbeOutcome {
    if !complete {
        return ProbeOutcome::Error;
    }
    match (status, code, credential_known) {
        (200..=299, _, true) => ProbeOutcome::Allow,
        (403, Some("AccessDenied"), true) => ProbeOutcome::Deny,
        (501, Some("NotImplemented"), _) => ProbeOutcome::Unsupported,
        _ => ProbeOutcome::Error,
    }
}
pub fn validate_setup(setup: &SeedBundle) -> Result<()> {
    let input = ScenarioInput {
        id: "setup-seed-001".into(),
        title: "seed".into(),
        target: "lws".into(),
        auth_mode: "strict".into(),
        setup: setup.clone(),
        task: "seed".into(),
        expect: vec![],
        expected_finding: None,
        retest: None,
        success_criteria: vec![],
        budget: Budget::default(),
        deviation: Deviation::default(),
    };
    input
        .validate()
        .map_err(|_| anyhow::anyhow!("invalid seed setup or unsupported policy syntax"))?;
    Ok(())
}
pub fn service_command(path: &Path, config: &Config) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if !config.development {
        let uid = config.service_uid;
        let gid = config.service_gid;
        // Runs between fork and exec; only async-signal-safe libc calls.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    child_guard(&mut command);
    command.as_std_mut().process_group(0);
    command
}

/// Linux VM children must not outlive a crashed root supervisor.
pub fn child_guard(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}
pub async fn stop(child: &mut Option<Child>, signal: i32, seconds: u64) -> Result<()> {
    let Some(mut process) = child.take() else {
        return Ok(());
    };
    if process.try_wait()?.is_some() {
        bail!("managed child exited before finalization");
    }
    if let Some(pid) = process.id() {
        unsafe {
            libc::kill(pid as i32, signal);
        }
    }
    match tokio::time::timeout(Duration::from_secs(seconds), process.wait()).await {
        Ok(status) => {
            let status = status?;
            ensure!(
                status.success() || status.signal() == Some(signal),
                "managed child reported failure"
            );
            Ok(())
        }
        Err(_) => {
            let _ = process.kill().await;
            let _ = process.wait().await;
            bail!("managed child shutdown timeout");
        }
    }
}
pub async fn start_lws(config: &Config, key: &str, client: &HttpClient) -> Result<Child> {
    let mut command = service_command(&config.lws, config);
    command
        .env("LWS_BIND_ADDR", config.upstream.to_string())
        .env("LWS_AUTH_MODE", "strict")
        .env("LWS_ROOT_ACCESS_KEY_ID", key)
        .env("LWS_DATA_DIR", &config.data_dir);
    let mut child = command.spawn().context("start LWS")?;
    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
    while Instant::now() < deadline {
        ensure!(child.try_wait()?.is_none(), "LWS exited during readiness");
        let req = Request::builder()
            .uri(format!("{}/_lws/health", config.endpoint()))
            .body(proxy::full(Vec::<u8>::new()))?;
        if let Ok(response) = proxy::request(client, req, 1).await {
            if response.status == 200
                && serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .is_some_and(|v| v["status"] == "ok" && v["auth"] == "strict")
            {
                return Ok(child);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    bail!("LWS readiness timeout")
}
// Avoid writing policy/body data to argv for object uploads. Temporary files are
// root-private; the seed bundle itself is removed by the authenticated controller.
struct PrivateFile(std::path::PathBuf);
impl PrivateFile {
    fn write(config: &Config, bytes: &[u8]) -> Result<Self> {
        let path = config.state_dir.join(format!("seed-{}", random_secret()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let guard = Self(path);
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(guard)
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
pub async fn aws(config: &Config, key: &str, args: &[String]) -> Result<Value> {
    let mut command = Command::new(&config.aws);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .env("AWS_ACCESS_KEY_ID", key)
        .env("AWS_SECRET_ACCESS_KEY", "tempest-local-dummy")
        .env("AWS_DEFAULT_REGION", capability::REGION)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", "/dev/null")
        .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
        .env("AWS_PAGER", "")
        .args([
            "--endpoint-url",
            &config.endpoint(),
            "--region",
            capability::REGION,
            "--output",
            "json",
            "--cli-connect-timeout",
            "2",
            "--cli-read-timeout",
            "10",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    child_guard(&mut command);
    let mut child = command.spawn().context("start local AWS CLI")?;
    let stdout = child.stdout.take().context("AWS CLI stdout unavailable")?;
    let read = async {
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        stdout.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "AWS CLI response exceeds control limit"
        );
        let status = child.wait().await?;
        ensure!(status.success(), "local AWS CLI operation failed");
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&bytes).context("invalid AWS CLI JSON")
        }
    };
    match tokio::time::timeout(Duration::from_secs(config.timeout_seconds), read).await {
        Ok(result) => result,
        Err(_) => {
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("local AWS CLI timeout");
        }
    }
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
pub async fn populate(config: &Config, key: &str, bundle: &SeedBundle) -> Result<AccessKeys> {
    let mut keys = AccessKeys::new();
    for user in &bundle.users {
        aws(
            config,
            key,
            &strings(&["iam", "create-user", "--user-name", &user.name]),
        )
        .await?;
        let credentials = aws(
            config,
            key,
            &strings(&["iam", "create-access-key", "--user-name", &user.name]),
        )
        .await?;
        let access = credentials
            .pointer("/AccessKey/AccessKeyId")
            .and_then(Value::as_str)
            .context("AWS CLI did not return AccessKeyId")?;
        keys.insert(user.name.clone(), access.into());
        let policy = PrivateFile::write(config, &serde_json::to_vec(&user.policy)?)?;
        aws(
            config,
            key,
            &strings(&[
                "iam",
                "put-user-policy",
                "--user-name",
                &user.name,
                "--policy-name",
                "tempest",
                "--policy-document",
                &format!("file://{}", policy.0.display()),
            ]),
        )
        .await?;
    }
    for bucket in &bundle.buckets {
        aws(
            config,
            key,
            &strings(&["s3api", "create-bucket", "--bucket", &bucket.name]),
        )
        .await?;
        for object in &bucket.objects {
            let body = PrivateFile::write(config, object.body.as_bytes())?;
            aws(
                config,
                key,
                &strings(&[
                    "s3api",
                    "put-object",
                    "--bucket",
                    &bucket.name,
                    "--key",
                    &object.key,
                    "--body",
                    body.0.to_str().context("private body path encoding")?,
                ]),
            )
            .await?;
        }
    }
    for queue in &bundle.queues {
        aws(
            config,
            key,
            &strings(&["sqs", "create-queue", "--queue-name", &queue.name]),
        )
        .await?;
    }
    Ok(keys)
}
pub async fn admin_check(
    config: &Config,
    key: &str,
    client: &HttpClient,
) -> Result<ResponseSummary> {
    let req = authenticated(
        config,
        key,
        Method::POST,
        "/",
        b"Action=ListUsers".to_vec(),
        Some("application/x-www-form-urlencoded"),
    )?;
    proxy::request(client, req, config.timeout_seconds).await
}
fn authenticated(
    config: &Config,
    key: &str,
    method: Method,
    path: &str,
    body: Vec<u8>,
    content_type: Option<&str>,
) -> Result<Request<HttpBody>> {
    ensure!(
        !key.is_empty()
            && key.len() <= 256
            && key
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"/ ,".contains(&b)),
        "invalid simulated access key"
    );
    let mut builder=Request::builder().method(method).uri(format!("{}{path}",config.endpoint()))
        .header("authorization",format!("AWS4-HMAC-SHA256 Credential={key}/local/{}/s3/aws4_request, SignedHeaders=host, Signature=local",capability::REGION));
    if let Some(value) = content_type {
        builder = builder.header("content-type", value);
    }
    Ok(builder.body(proxy::full(body))?)
}
pub async fn probe(
    config: &Config,
    request: &ProbeRequest,
    setup: &SeedBundle,
    client: &HttpClient,
    credential_known: bool,
) -> Result<ProbeResult> {
    let Some(cap) = capability::lookup(&request.api) else {
        bail!("unknown probe API");
    };
    ensure!(
        matches!(cap.support, Support::Static) || request.api == "s3:PutBucketNotification",
        "probe API requires unsupported input parameters"
    );
    tempest_model::validation::resource(&request.resource, cap.resource, setup)
        .map_err(|_| anyhow::anyhow!("invalid probe resource reference"))?;
    let mut target = "/".to_string();
    let method;
    let mut body = Vec::new();
    let mut content_type = None;
    if request.api.starts_with("s3:") {
        if request.resource != "*" {
            let resource = request
                .resource
                .strip_prefix("arn:aws:s3:::")
                .context("invalid S3 resource")?;
            target = format!(
                "/{}",
                percent_encoding::utf8_percent_encode(resource, S3_PATH)
            );
            if request.api == "s3:PutObject" {
                let (bucket, key) = resource
                    .split_once('/')
                    .context("invalid object reference")?;
                body = setup
                    .buckets
                    .iter()
                    .find(|b| b.name == bucket)
                    .and_then(|b| b.objects.iter().find(|o| o.key == key))
                    .context("object body missing")?
                    .body
                    .as_bytes()
                    .to_vec();
            }
        }
        if request.api == "s3:PutBucketNotification" {
            target.push_str("?notification");
        }
        method = match request.api.as_str() {
            "s3:CreateBucket" | "s3:PutObject" | "s3:PutBucketNotification" => Method::PUT,
            "s3:DeleteBucket" | "s3:DeleteObject" => Method::DELETE,
            _ => Method::GET,
        };
    } else if request.api.starts_with("sqs:") {
        let action = request.api.strip_prefix("sqs:").unwrap();
        let mut params = vec![("Action".to_string(), action.to_string())];
        if request.resource != "*" {
            let queue = request
                .resource
                .rsplit(':')
                .next()
                .context("invalid queue resource")?;
            if matches!(action, "CreateQueue" | "GetQueueUrl") {
                params.push(("QueueName".into(), queue.into()));
            } else {
                params.push((
                    "QueueUrl".into(),
                    format!("{}/{}/{queue}", config.endpoint(), capability::ACCOUNT),
                ));
            }
        }
        if action == "GetQueueAttributes" {
            params.push(("AttributeName.1".into(), "All".into()));
        }
        body = serde_urlencoded::to_string(params)?.into_bytes();
        method = Method::POST;
        content_type = Some("application/x-www-form-urlencoded");
    } else if request.api == "ses:ListIdentities" {
        body = b"Action=ListIdentities".to_vec();
        method = Method::POST;
        content_type = Some("application/x-www-form-urlencoded");
    } else {
        bail!("probe API is not representable");
    }
    let req = authenticated(
        config,
        &request.access_key_id,
        method,
        &target,
        body,
        content_type,
    )?;
    match proxy::request(client, req, config.timeout_seconds).await {
        Ok(response) => Ok(ProbeResult {
            outcome: classify(
                response.status,
                response.error_code.as_deref(),
                response.complete,
                credential_known,
            ),
            status: Some(response.status),
            error_code: response.error_code,
            complete: response.complete,
            credential_known,
        }),
        Err(_) => Ok(ProbeResult {
            outcome: ProbeOutcome::Error,
            status: None,
            error_code: None,
            complete: false,
            credential_known,
        }),
    }
}
