use crate::{Error, Result};
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout: Option<Duration>,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        self.body.zeroize();
        for (_, value) in &mut self.headers {
            value.zeroize();
        }
    }
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"[REDACTED]")
            .field("body_length", &self.body.len())
            .field("timeout", &self.timeout)
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
        let timeout = Duration::from_secs(5);
        Self {
            agent: ureq::Agent::config_builder()
                .timeout_connect(Some(timeout))
                .timeout_recv_response(Some(timeout))
                .timeout_recv_body(Some(timeout))
                .http_status_as_error(false)
                .build()
                .new_agent(),
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
        let response = match request.method {
            "GET" => {
                let mut builder = self.agent.get(&request.url);
                for (name, value) in &request.headers {
                    builder = builder.header(name, value);
                }
                if let Some(timeout) = request.timeout {
                    builder = builder.config().timeout_global(Some(timeout)).build();
                }
                builder.call()
            }
            "POST" => {
                let mut builder = self.agent.post(&request.url);
                for (name, value) in &request.headers {
                    builder = builder.header(name, value);
                }
                if let Some(timeout) = request.timeout {
                    builder = builder.config().timeout_global(Some(timeout)).build();
                }
                builder.send(&request.body)
            }
            other => {
                return Err(Error::Http(format!("unsupported HTTP method {other}")));
            }
        };
        match response {
            Ok(response) => read_response(response),
            Err(error) => Err(Error::Http(format!("request failed: {error}"))),
        }
    }
}

fn read_response(mut response: ureq::http::Response<ureq::Body>) -> Result<HttpResponse> {
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response.body_mut().as_reader().read_to_end(&mut body)?;
    Ok(HttpResponse { status, body })
}
