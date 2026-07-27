use super::http::{HttpRequest, HttpTransport};
use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use url::Url;

pub const POSTURE_GATE_TIMEOUT_SECONDS: u64 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostureDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PostureEvaluation {
    pub local_allowed: bool,
    pub controller_decision: PostureDecision,
    pub failed_checks: Vec<Value>,
    pub user_notice: Option<Value>,
    raw: Value,
}

impl PostureEvaluation {
    pub fn allowed(&self) -> bool {
        self.local_allowed && self.controller_decision == PostureDecision::Allow
    }

    pub const fn raw(&self) -> &Value {
        &self.raw
    }
}

#[derive(Debug, Serialize)]
struct EvaluateRequest<'a> {
    user_id: &'a str,
    version: i64,
    check_results: &'a [Value],
}

pub(crate) fn evaluate<T: HttpTransport>(
    transport: &T,
    config_url: &str,
    access_token: Option<&str>,
    user_id: &str,
    version: i64,
    check_results: &[Value],
) -> Result<PostureEvaluation> {
    if user_id.is_empty() {
        return Err(Error::Controller(
            "posture user_id must not be empty".into(),
        ));
    }
    let body = serde_json::to_vec(&EvaluateRequest {
        user_id,
        version,
        check_results,
    })
    .map_err(|error| Error::Controller(format!("serialize posture request: {error}")))?;
    let mut headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("X-Mobile-Api-Version".into(), "4".into()),
    ];
    if let Some(token) = access_token.filter(|token| !token.is_empty()) {
        headers.push(("Authorization".into(), format!("Bearer {token}")));
    }
    let response = transport.execute(HttpRequest {
        method: "POST",
        url: posture_endpoint(config_url)?,
        headers,
        body,
        timeout: Some(std::time::Duration::from_secs(POSTURE_GATE_TIMEOUT_SECONDS)),
    })?;
    match response.status {
        200 => parse_response(
            serde_json::from_slice(&response.body)
                .map_err(|error| Error::Controller(format!("invalid posture response: {error}")))?,
        ),
        401 => Err(Error::ControllerUnauthorized),
        409 => Err(Error::PostureVersionMismatch),
        503 => Err(Error::PostureConfigUnavailable),
        status => Err(Error::Controller(format!(
            "posture evaluate returned HTTP {status}"
        ))),
    }
}

pub fn posture_version(configuration: &Value) -> Result<i64> {
    let version = match configuration.get("version") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(version)) => version
            .as_i64()
            .ok_or_else(|| Error::Controller("posture version is outside i64 range".into()))?,
        Some(Value::String(version)) => version
            .parse::<i64>()
            .map_err(|_| Error::Controller("posture version is not a decimal integer".into()))?,
        Some(_) => {
            return Err(Error::Controller(
                "posture version must be an integer or decimal string".into(),
            ));
        }
    };
    if version < 0 {
        return Err(Error::Controller(
            "posture version must not be negative".into(),
        ));
    }
    Ok(version)
}

pub(crate) fn posture_gate_version(configuration: &Value) -> Result<Option<i64>> {
    let version = posture_version(configuration)?;
    Ok((version != 0).then_some(version))
}

fn parse_response(value: Value) -> Result<PostureEvaluation> {
    let root = value
        .as_object()
        .ok_or_else(|| Error::Controller("posture response must be an object".into()))?;
    let raw = root.get("data").cloned().unwrap_or(value);
    let object = raw
        .as_object()
        .ok_or_else(|| Error::Controller("posture response data must be an object".into()))?;
    let local_allowed = object.get("local_gate").and_then(Value::as_bool) == Some(true);
    let posture_ack = object
        .get("posture_ack")
        .ok_or_else(|| Error::Controller("posture response has no posture_ack".into()))?;
    let decision = ack_decision(posture_ack)?;
    let failed_checks = posture_ack
        .as_object()
        .and_then(|ack| ack.get("failed_checks"))
        .map(|checks| match checks {
            Value::Array(checks) => checks.clone(),
            value => vec![value.clone()],
        })
        .unwrap_or_default();
    Ok(PostureEvaluation {
        local_allowed,
        controller_decision: decision,
        failed_checks,
        user_notice: object
            .get("user_notice")
            .filter(|notice| notice.is_object())
            .cloned(),
        raw,
    })
}

fn ack_decision(value: &Value) -> Result<PostureDecision> {
    let decision = value.as_str().or_else(|| {
        let object = value.as_object()?;
        object
            .get("decision")
            .or_else(|| object.get("status"))
            .and_then(Value::as_str)
    });
    match decision.map(str::to_ascii_uppercase).as_deref() {
        Some("DENY") => Ok(PostureDecision::Deny),
        Some(_) => Ok(PostureDecision::Allow),
        None => Err(Error::Controller("invalid posture_ack decision".into())),
    }
}

fn posture_endpoint(config_url: &str) -> Result<String> {
    let mut url = Url::parse(config_url)
        .map_err(|error| Error::Controller(format!("invalid config URL: {error}")))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Controller(
            "config URL must be HTTPS without credentials or a fragment".into(),
        ));
    }
    let path = url.path().trim_end_matches('/');
    let base = path.strip_suffix("/config").unwrap_or(path);
    url.set_path(&format!("{base}/posture/evaluate"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::http::HttpResponse;
    use std::sync::Mutex;

    struct MockTransport {
        request: Mutex<Option<HttpRequest>>,
        response: HttpResponse,
    }

    impl HttpTransport for MockTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
            *self.request.lock().unwrap() = Some(request);
            Ok(self.response.clone())
        }
    }

    #[test]
    fn sends_posture_contract_and_requires_both_gates() {
        let transport = MockTransport {
            request: Mutex::new(None),
            response: HttpResponse {
                status: 200,
                body: br#"{"local_gate":true,"posture_ack":{"decision":"DENY","failed_checks":{"code":"FW001"}},"user_notice":{"message":"blocked"}}"#.to_vec(),
            },
        };
        let result = evaluate(
            &transport,
            "https://controller.example/config",
            Some("access"),
            "user-1",
            7,
            &[serde_json::json!({"type":"firewall","passed":false})],
        )
        .unwrap();
        assert!(!result.allowed());
        assert_eq!(result.failed_checks.len(), 1);
        let request = transport.request.lock().unwrap().take().unwrap();
        assert_eq!(request.url, "https://controller.example/posture/evaluate");
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).unwrap(),
            serde_json::json!({
                "user_id": "user-1",
                "version": 7,
                "check_results": [{"type":"firewall","passed":false}]
            })
        );
    }

    #[test]
    fn only_an_explicit_deny_blocks_the_controller_gate() {
        assert_eq!(
            ack_decision(&Value::String("WARN".into())).unwrap(),
            PostureDecision::Allow
        );
        assert_eq!(
            ack_decision(&serde_json::json!({"status": "pending"})).unwrap(),
            PostureDecision::Allow
        );
        assert_eq!(
            ack_decision(&serde_json::json!({"decision": "deny"})).unwrap(),
            PostureDecision::Deny
        );
        assert!(ack_decision(&serde_json::json!({"decision": 1})).is_err());
    }

    #[test]
    fn absent_local_gate_denies_and_non_object_notice_is_ignored() {
        let evaluation = parse_response(serde_json::json!({
            "posture_ack": "ALLOW",
            "user_notice": "not-a-map"
        }))
        .unwrap();
        assert!(!evaluation.allowed());
        assert!(evaluation.user_notice.is_none());
    }

    #[test]
    fn maps_special_status_codes() {
        let transport = MockTransport {
            request: Mutex::new(None),
            response: HttpResponse {
                status: 409,
                body: Vec::new(),
            },
        };
        assert!(matches!(
            evaluate(
                &transport,
                "https://controller.example",
                None,
                "user",
                1,
                &[]
            ),
            Err(Error::PostureVersionMismatch)
        ));
    }

    #[test]
    fn zero_or_missing_version_is_disabled_posture() {
        assert_eq!(
            posture_gate_version(&serde_json::json!({
                "version": 0,
                "updated": false
            }))
            .unwrap(),
            None
        );
        assert_eq!(
            posture_gate_version(&serde_json::json!({"updated": false})).unwrap(),
            None
        );
        assert_eq!(
            posture_gate_version(&serde_json::json!({"version": "0"})).unwrap(),
            None
        );
        assert_eq!(
            posture_gate_version(&serde_json::json!({"version": 7})).unwrap(),
            Some(7)
        );
        assert_eq!(
            posture_gate_version(&serde_json::json!({"version": "7"})).unwrap(),
            Some(7)
        );
        assert!(posture_gate_version(&serde_json::json!({"version": -1})).is_err());
    }
}
