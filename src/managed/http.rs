use crate::{Error, Result};
use std::io::Read;
use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body_length", &self.body.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_length", &self.body.len())
            .finish()
    }
}

pub trait HttpTransport: Send + Sync {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse>;
}

pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        let timeout = Duration::from_secs(15);
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(timeout)
                .timeout_read(timeout)
                .timeout_write(timeout)
                .build(),
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTransport for UreqTransport {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse> {
        let mut builder = match request.method {
            "GET" => self.agent.get(&request.url),
            "POST" => self.agent.post(&request.url),
            other => {
                return Err(Error::Http(format!("unsupported HTTP method {other}")));
            }
        };
        for (name, value) in &request.headers {
            builder = builder.set(name, value);
        }
        let response = match request.method {
            "GET" => builder.call(),
            "POST" => builder.send_bytes(&request.body),
            _ => unreachable!("method checked above"),
        };
        match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => read_response(response),
            Err(error) => Err(Error::Http(format!("request failed: {error}"))),
        }
    }
}

fn read_response(response: ureq::Response) -> Result<HttpResponse> {
    let status = response.status();
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::Http("response exceeds 1 MiB limit".into()));
    }
    Ok(HttpResponse { status, body })
}
