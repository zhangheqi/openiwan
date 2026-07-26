use super::{RelayTcpStream, Target, TcpConnector};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, HeaderName, HeaderValue, LOCATION, UPGRADE};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::{Client as HttpClient, Error as HttpClientError};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openiwan::{Error, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tower_service::Service;
use tracing::{debug, warn};
use url::Host;

type BoxError = Box<dyn StdError + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type ProxyClient = HttpClient<HttpConnector, Incoming>;

pub(super) fn build_tls_connector(ca_certificates: &[PathBuf]) -> Result<TlsConnector> {
    let native = rustls_native_certs::load_native_certs();
    for error in &native.errors {
        warn!(%error, "failed to load one native root certificate");
    }
    let mut roots = RootCertStore::empty();
    let (native_added, native_ignored) = roots.add_parsable_certificates(native.certs);
    if native_ignored > 0 {
        warn!(
            native_ignored,
            "ignored invalid certificates from native root store"
        );
    }

    let mut custom_added = 0_usize;
    for path in ca_certificates {
        let file = File::open(path).map_err(|error| {
            Error::InvalidConfig(format!("cannot open CA file {}: {error}", path.display()))
        })?;
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<io::Result<Vec<_>>>()
            .map_err(|error| {
                Error::InvalidConfig(format!("cannot parse CA file {}: {error}", path.display()))
            })?;
        if certificates.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "CA file {} contains no certificates",
                path.display()
            )));
        }
        for certificate in certificates {
            roots.add(certificate).map_err(|error| {
                Error::InvalidConfig(format!(
                    "invalid certificate in CA file {}: {error}",
                    path.display()
                ))
            })?;
            custom_added += 1;
        }
    }
    if native_added + custom_added == 0 {
        return Err(Error::InvalidConfig(
            "no usable TLS root certificates were loaded".into(),
        ));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::Http(format!("select TLS protocol versions: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_config)))
}

#[derive(Clone)]
pub(super) struct HttpForwarder {
    state: Arc<ProxyState>,
}

impl HttpForwarder {
    pub(super) fn new(tcp: TcpConnector, target: Target, tls: Option<TlsConnector>) -> Self {
        debug_assert!(target.is_http());
        debug_assert_eq!(target.uses_tls(), tls.is_some());
        let connector = HttpConnector {
            tcp,
            target: target.clone(),
            tls,
        };
        let client = HttpClient::builder(TokioExecutor::new()).build(connector);
        Self {
            state: Arc::new(ProxyState { client, target }),
        }
    }

    pub(super) async fn serve(&self, stream: tokio::net::TcpStream, peer: SocketAddr) {
        let state = Arc::clone(&self.state);
        let service = service_fn(move |request| proxy_request(request, Arc::clone(&state)));
        if let Err(error) = http1::Builder::new()
            .keep_alive(true)
            .serve_connection(TokioIo::new(stream), service)
            .await
        {
            debug!(%peer, %error, "local HTTP connection ended with an error");
        }
    }
}

#[derive(Clone)]
struct HttpConnector {
    tcp: TcpConnector,
    target: Target,
    tls: Option<TlsConnector>,
}

impl HttpConnector {
    async fn connect(&self, uri: &Uri) -> std::result::Result<IwanConnection, BoxError> {
        if !matches_target_uri(&self.target, uri) {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "HTTP forward connector rejected a non-configured destination",
            )
            .into());
        }

        let server_name = self
            .target
            .uses_tls()
            .then(|| {
                ServerName::try_from(self.target.host.clone())
                    .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error.to_string()))
            })
            .transpose()?;
        let tls = self.tls.clone();
        self.tcp
            .connect_with(move |stream| {
                let tls = tls.clone();
                let server_name = server_name.clone();
                async move {
                    let stream = RelayTcpStream::new(stream);
                    let Some(server_name) = server_name else {
                        return Ok(IwanConnection::Plain(TokioIo::new(stream)));
                    };
                    let tls = tls
                        .as_ref()
                        .expect("HTTPS target has a configured TLS connector");
                    let stream = tls
                        .connect(server_name, stream)
                        .await
                        .map_err(io::Error::other)?;
                    Ok(IwanConnection::Tls(Box::new(TokioIo::new(stream))))
                }
            })
            .await
            .map_err(Into::into)
    }
}

fn matches_target_uri(target: &Target, uri: &Uri) -> bool {
    uri.scheme_str() == Some(target.scheme.as_str())
        && uri
            .authority()
            .is_some_and(|authority| authority == target.authority.as_str())
}

impl Service<Uri> for HttpConnector {
    type Response = IwanConnection;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move { connector.connect(&uri).await })
    }
}

enum IwanConnection {
    Plain(TokioIo<RelayTcpStream>),
    Tls(Box<TokioIo<TlsStream<RelayTcpStream>>>),
}

impl Connection for IwanConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl HyperRead for IwanConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperRead::poll_read(Pin::new(stream), context, buffer),
            Self::Tls(stream) => HyperRead::poll_read(Pin::new(stream.as_mut()), context, buffer),
        }
    }
}

impl HyperWrite for IwanConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_write(Pin::new(stream), context, buffer),
            Self::Tls(stream) => HyperWrite::poll_write(Pin::new(stream.as_mut()), context, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_flush(Pin::new(stream), context),
            Self::Tls(stream) => HyperWrite::poll_flush(Pin::new(stream.as_mut()), context),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => HyperWrite::poll_shutdown(Pin::new(stream), context),
            Self::Tls(stream) => HyperWrite::poll_shutdown(Pin::new(stream.as_mut()), context),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => HyperWrite::is_write_vectored(stream),
            Self::Tls(stream) => HyperWrite::is_write_vectored(stream.as_ref()),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => {
                HyperWrite::poll_write_vectored(Pin::new(stream), context, buffers)
            }
            Self::Tls(stream) => {
                HyperWrite::poll_write_vectored(Pin::new(stream.as_mut()), context, buffers)
            }
        }
    }
}

struct ProxyState {
    client: ProxyClient,
    target: Target,
}

async fn proxy_request(
    mut request: Request<Incoming>,
    state: Arc<ProxyState>,
) -> std::result::Result<Response<ProxyBody>, Infallible> {
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return Ok(error_response(StatusCode::BAD_REQUEST));
    }
    let uri = match request_uri(&state.target, request.uri()) {
        Ok(uri) => uri,
        Err(error) => {
            warn!(%error, "rejected malformed local HTTP request");
            return Ok(error_response(StatusCode::BAD_REQUEST));
        }
    };
    strip_hop_by_hop(request.headers_mut());
    let host = match HeaderValue::from_str(&state.target.authority) {
        Ok(host) => host,
        Err(error) => {
            warn!(%error, "configured target authority is not a valid Host header");
            return Ok(error_response(StatusCode::BAD_GATEWAY));
        }
    };
    request.headers_mut().insert(HOST, host);
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;

    match state.client.request(request).await {
        Ok(mut response) => {
            strip_hop_by_hop(response.headers_mut());
            rewrite_location(response.headers_mut(), &state.target);
            Ok(response.map(|body| {
                body.map_err(|error| -> BoxError { Box::new(error) })
                    .boxed_unsync()
            }))
        }
        Err(error) => {
            let status = if is_timeout_error(&error) {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            };
            warn!(%error, "HTTP forward target request failed");
            Ok(error_response(status))
        }
    }
}

fn request_uri(target: &Target, incoming: &Uri) -> Result<Uri> {
    let path_and_query = incoming
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    Uri::builder()
        .scheme(target.scheme.as_str())
        .authority(target.authority.as_str())
        .path_and_query(path_and_query)
        .build()
        .map_err(|error| Error::Http(format!("build target request URI: {error}")))
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn rewrite_location(headers: &mut HeaderMap, target: &Target) {
    let Some(value) = headers.get(LOCATION) else {
        return;
    };
    let Ok(value) = value.to_str() else {
        return;
    };
    let Ok(location) = url::Url::parse(value) else {
        return;
    };
    let same_host = match location.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case(&target.host),
        Some(Host::Ipv4(address)) => target.host.parse() == Ok(address),
        Some(Host::Ipv6(address)) => target.host.parse() == Ok(address),
        None => false,
    };
    if location.scheme() != target.scheme.as_str()
        || !same_host
        || location.port_or_known_default() != Some(target.port)
    {
        return;
    }
    let mut relative = location.path().to_owned();
    if let Some(query) = location.query() {
        relative.push('?');
        relative.push_str(query);
    }
    if let Some(fragment) = location.fragment() {
        relative.push('#');
        relative.push_str(fragment);
    }
    if let Ok(value) = HeaderValue::from_str(&relative) {
        headers.insert(LOCATION, value);
    }
}

fn is_timeout_error(error: &HttpClientError) -> bool {
    let mut current: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == ErrorKind::TimedOut)
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn error_response(status: StatusCode) -> Response<ProxyBody> {
    let message = match status {
        StatusCode::BAD_REQUEST => "bad request\n",
        StatusCode::GATEWAY_TIMEOUT => "target connection timed out\n",
        _ => "target unavailable\n",
    };
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::from_static(message.as_bytes()))
                .map_err(|never| -> BoxError { match never {} })
                .boxed_unsync(),
        )
        .expect("static HTTP error response is valid")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{linked_userspace_nets, test_session};
    use super::super::{
        CachedResolution, ConnectorSettings, DnsConfig, DnsMode, ForwardConfig, Net,
        ResolutionSource,
    };
    use super::*;
    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use rustls::ServerConfig;
    use std::fs::File;
    use std::io::BufReader;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{Notify, oneshot};
    use tokio::time::{Instant, timeout};
    use tokio_rustls::TlsAcceptor;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
    }

    struct ObservedRequest {
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    fn test_tls_acceptor() -> TlsAcceptor {
        let mut certificate_reader =
            BufReader::new(File::open(fixture_path("forward-server.pem")).unwrap());
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        let mut key_reader =
            BufReader::new(File::open(fixture_path("forward-server-key.pem")).unwrap());
        let key = rustls_pemfile::private_key(&mut key_reader)
            .unwrap()
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    }

    async fn test_connector(
        net: Arc<Net>,
        client_ip: Ipv4Addr,
        target: Target,
        target_address: SocketAddr,
        connect_timeout: Duration,
    ) -> TcpConnector {
        let connector = TcpConnector::new(
            net,
            &test_session(client_ip),
            ConnectorSettings {
                target,
                dns_mode: DnsMode::Auto,
                dns_servers: Vec::new(),
                dns_timeout: Duration::from_secs(1),
                timeout: connect_timeout,
            },
        );
        *connector.dns_cache.lock().await = Some(CachedResolution {
            addresses: vec![target_address],
            source: ResolutionSource::SystemDns,
            expires_at: Instant::now() + Duration::from_secs(60),
        });
        connector
    }

    async fn request_via_local_proxy(forwarder: HttpForwarder) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            forwarder.serve(stream, peer).await;
        });

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /secure HTTP/1.1\r\nHost: local.example\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), proxy)
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    #[test]
    fn preserves_path_and_query_for_fixed_target() {
        let target = Target::parse("https://api.example.test:8443").unwrap();
        let incoming = "/v1/profile?full=true".parse::<Uri>().unwrap();
        assert_eq!(
            request_uri(&target, &incoming).unwrap(),
            "https://api.example.test:8443/v1/profile?full=true"
        );
    }

    #[test]
    fn connector_accepts_the_configured_ipv6_authority() {
        let target = Target::parse("https://[2001:db8::25]:8443").unwrap();
        let uri = request_uri(&target, &"/v1/profile".parse().unwrap()).unwrap();
        assert!(matches_target_uri(&target, &uri));
    }

    #[test]
    fn strips_standard_and_connection_named_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-remove"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-remove", HeaderValue::from_static("yes"));
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-remove"));
        assert_eq!(headers["authorization"], "Bearer token");
    }

    #[test]
    fn rewrites_only_same_origin_locations() {
        let target = Target::parse("https://api.example.test").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://api.example.test/login?next=%2F"),
        );
        rewrite_location(&mut headers, &target);
        assert_eq!(headers[LOCATION], "/login?next=%2F");

        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://other.example.test/login"),
        );
        rewrite_location(&mut headers, &target);
        assert_eq!(headers[LOCATION], "https://other.example.test/login");

        let target = Target::parse("https://[2001:db8::25]:8443").unwrap();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://[2001:db8::25]:8443/v1?full=true"),
        );
        rewrite_location(&mut headers, &target);
        assert_eq!(headers[LOCATION], "/v1?full=true");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn forwards_streaming_http_and_rewrites_origin_semantics_end_to_end() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 20, 1);
            let server_ip = Ipv4Addr::new(198, 18, 20, 2);
            let server_port = 18_082;
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let target_uri = format!("http://{server_ip}:{server_port}");
            let target = Target::parse(&target_uri).unwrap();

            let (first_request_chunk_sender, first_request_chunk) = oneshot::channel();
            let first_request_chunk_sender =
                Arc::new(tokio::sync::Mutex::new(Some(first_request_chunk_sender)));
            let (observed_request_sender, observed_request) = oneshot::channel();
            let observed_request_sender =
                Arc::new(tokio::sync::Mutex::new(Some(observed_request_sender)));
            let second_response_chunk = Arc::new(Notify::new());

            let server_address = SocketAddr::new(server_ip.into(), server_port);
            let mut upstream_listener = server_net.tcp_bind(server_address).await.unwrap();
            let absolute_location = format!("{target_uri}/next?from=proxy#done");
            let upstream = {
                let first_request_chunk_sender = Arc::clone(&first_request_chunk_sender);
                let observed_request_sender = Arc::clone(&observed_request_sender);
                let second_response_chunk = Arc::clone(&second_response_chunk);
                tokio::spawn(async move {
                    let (stream, _) = upstream_listener.accept().await.unwrap();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let first_request_chunk_sender = Arc::clone(&first_request_chunk_sender);
                        let observed_request_sender = Arc::clone(&observed_request_sender);
                        let second_response_chunk = Arc::clone(&second_response_chunk);
                        let absolute_location = absolute_location.clone();
                        async move {
                            let (parts, mut body) = request.into_parts();
                            let mut received = Vec::new();
                            while let Some(frame) = body.frame().await {
                                let frame = frame.unwrap();
                                if let Some(data) = frame.data_ref() {
                                    received.extend_from_slice(data);
                                    if let Some(sender) =
                                        first_request_chunk_sender.lock().await.take()
                                    {
                                        let _ = sender.send(());
                                    }
                                }
                            }
                            if let Some(sender) = observed_request_sender.lock().await.take() {
                                let _ = sender.send(ObservedRequest {
                                    uri: parts.uri,
                                    headers: parts.headers,
                                    body: received,
                                });
                            }

                            let events = futures::stream::unfold(
                                (0_u8, second_response_chunk),
                                |(state, release)| async move {
                                    match state {
                                        0 => Some((
                                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                                b"data: first\n\n",
                                            ))),
                                            (1, release),
                                        )),
                                        1 => {
                                            release.notified().await;
                                            Some((
                                                Ok::<_, Infallible>(Frame::data(
                                                    Bytes::from_static(b"data: second\n\n"),
                                                )),
                                                (2, release),
                                            ))
                                        }
                                        _ => None,
                                    }
                                },
                            );
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::FOUND)
                                    .header("content-type", "text/event-stream")
                                    .header(LOCATION, absolute_location)
                                    .header(CONNECTION, "close, x-upstream-remove")
                                    .header("x-upstream-remove", "secret")
                                    .header("x-business-response", "preserved")
                                    .body(StreamBody::new(events))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(RelayTcpStream::new(stream)), service)
                        .await;
                })
            };

            let connector = TcpConnector::new(
                client_net,
                &test_session(client_ip),
                ConnectorSettings {
                    target: target.clone(),
                    dns_mode: DnsMode::Auto,
                    dns_servers: Vec::new(),
                    dns_timeout: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
            );
            let forwarder = HttpForwarder::new(connector, target.clone(), None);
            let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local_address = local_listener.local_addr().unwrap();
            let mut local_client = tokio::net::TcpStream::connect(local_address).await.unwrap();
            let (local_stream, peer) = local_listener.accept().await.unwrap();
            let proxy = {
                let forwarder = forwarder.clone();
                tokio::spawn(async move { forwarder.serve(local_stream, peer).await })
            };

            let request_head = format!(
                "POST /v1/events?topic=proxy HTTP/1.1\r\n\
                 Host: {local_address}\r\n\
                 Authorization: Bearer test-token\r\n\
                 X-Business-Request: preserved\r\n\
                 Connection: close, x-remove\r\n\
                 X-Remove: secret\r\n\
                 Proxy-Connection: keep-alive\r\n\
                 Transfer-Encoding: chunked\r\n\r\n\
                 5\r\nhello\r\n"
            );
            local_client
                .write_all(request_head.as_bytes())
                .await
                .unwrap();
            local_client.flush().await.unwrap();
            timeout(Duration::from_secs(5), first_request_chunk)
                .await
                .expect("upstream should receive the first request chunk before upload ends")
                .unwrap();
            local_client
                .write_all(b"6\r\n world\r\n0\r\n\r\n")
                .await
                .unwrap();
            local_client.flush().await.unwrap();

            let observed = timeout(Duration::from_secs(5), observed_request)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(observed.uri, "/v1/events?topic=proxy");
            assert_eq!(observed.headers[HOST], format!("{server_ip}:{server_port}"));
            assert_eq!(observed.headers["authorization"], "Bearer test-token");
            assert_eq!(observed.headers["x-business-request"], "preserved");
            assert!(!observed.headers.contains_key(CONNECTION));
            assert!(!observed.headers.contains_key("x-remove"));
            assert!(!observed.headers.contains_key("proxy-connection"));
            assert_eq!(observed.body, b"hello world");

            let mut response = Vec::new();
            let mut buffer = [0_u8; 1_024];
            timeout(Duration::from_secs(5), async {
                while !contains_bytes(&response, b"data: first\n\n") {
                    let length = local_client.read(&mut buffer).await.unwrap();
                    assert_ne!(length, 0, "response ended before the first SSE event");
                    response.extend_from_slice(&buffer[..length]);
                }
            })
            .await
            .expect("first SSE event should arrive without waiting for the second");
            assert!(!contains_bytes(&response, b"data: second\n\n"));
            second_response_chunk.notify_one();
            timeout(
                Duration::from_secs(5),
                local_client.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();

            let response_text = String::from_utf8(response).unwrap().to_ascii_lowercase();
            assert!(response_text.starts_with("http/1.1 302 found\r\n"));
            assert!(response_text.contains("content-type: text/event-stream\r\n"));
            assert!(response_text.contains("location: /next?from=proxy#done\r\n"));
            assert!(response_text.contains("x-business-response: preserved\r\n"));
            assert!(!response_text.contains("x-upstream-remove"));
            assert!(response_text.contains("data: first\n\n"));
            assert!(response_text.contains("data: second\n\n"));

            timeout(Duration::from_secs(5), proxy)
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), upstream)
                .await
                .unwrap()
                .unwrap();

            let rejected_client = tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(local_address).await.unwrap();
                stream
                    .write_all(
                        b"CONNECT other.example.test:443 HTTP/1.1\r\n\
                          Host: other.example.test:443\r\n\
                          Connection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                response
            });
            let (local_stream, peer) = local_listener.accept().await.unwrap();
            let rejected_proxy =
                tokio::spawn(async move { forwarder.serve(local_stream, peer).await });
            let rejected_response = timeout(Duration::from_secs(5), rejected_client)
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8(rejected_response)
                    .unwrap()
                    .starts_with("HTTP/1.1 400 Bad Request\r\n")
            );
            timeout(Duration::from_secs(5), rejected_proxy)
                .await
                .unwrap()
                .unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();
        });
    }

    #[test]
    fn ca_cert_is_rejected_before_file_access_for_non_https_targets() {
        let missing = PathBuf::from("this-forward-ca-file-does-not-exist.pem");
        for target in [
            "tcp://service.example.test:443",
            "http://service.example.test",
        ] {
            let error = ForwardConfig::new(
                "127.0.0.1:19384".parse().unwrap(),
                target,
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(1)).unwrap(),
                vec![missing.clone()],
                Duration::from_secs(1),
            )
            .err()
            .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("--ca-cert is only valid for an https:// target"),
                "unexpected error for {target}: {error}"
            );
        }

        assert!(
            ForwardConfig::new(
                "127.0.0.1:19384".parse().unwrap(),
                "https://service.example.test",
                DnsConfig::new(DnsMode::Auto, Vec::new(), Duration::from_secs(1)).unwrap(),
                vec![fixture_path("forward-ca.pem")],
                Duration::from_secs(1),
            )
            .is_ok()
        );
    }

    #[test]
    fn system_roots_build_an_https_connector_without_custom_ca() {
        assert!(build_tls_connector(&[]).is_ok());
    }

    #[test]
    fn custom_ca_accepts_matching_hostname_and_sends_sni() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 10, 1);
            let server_ip = Ipv4Addr::new(198, 18, 10, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let target_address = SocketAddr::new(server_ip.into(), 8_443);
            let mut listener = server_net.tcp_bind(target_address).await.unwrap();
            let acceptor = test_tls_acceptor();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let stream = acceptor.accept(RelayTcpStream::new(stream)).await.unwrap();
                (
                    stream.get_ref().1.server_name().map(str::to_owned),
                    stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
                )
            });

            let target = Target::parse("https://service.example.test:8443").unwrap();
            let tcp = test_connector(
                client_net,
                client_ip,
                target.clone(),
                target_address,
                Duration::from_secs(2),
            )
            .await;
            let connector = HttpConnector {
                tcp,
                target: target.clone(),
                tls: Some(build_tls_connector(&[fixture_path("forward-ca.pem")]).unwrap()),
            };
            let uri = request_uri(&target, &"/secure".parse().unwrap()).unwrap();
            let connection = timeout(Duration::from_secs(3), connector.connect(&uri))
                .await
                .unwrap();
            let connection_error = connection.as_ref().err().map(ToString::to_string);
            let metadata = timeout(Duration::from_secs(3), server).await;
            drop(connection);

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();

            assert!(
                connection_error.is_none(),
                "matching TLS connection failed: {connection_error:?}"
            );
            let metadata = metadata.unwrap().unwrap();
            assert_eq!(metadata.0.as_deref(), Some("service.example.test"));
            assert_eq!(metadata.1.as_deref(), Some(b"http/1.1".as_slice()));
        });
    }

    #[test]
    fn custom_ca_hostname_mismatch_is_mapped_to_bad_gateway() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 11, 1);
            let server_ip = Ipv4Addr::new(198, 18, 11, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let target_address = SocketAddr::new(server_ip.into(), 8_444);
            let mut listener = server_net.tcp_bind(target_address).await.unwrap();
            let acceptor = test_tls_acceptor();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                acceptor.accept(RelayTcpStream::new(stream)).await
            });

            let target = Target::parse("https://wrong.example.test:8444").unwrap();
            let tcp = test_connector(
                client_net,
                client_ip,
                target.clone(),
                target_address,
                Duration::from_secs(2),
            )
            .await;
            let forwarder = HttpForwarder::new(
                tcp,
                target,
                Some(build_tls_connector(&[fixture_path("forward-ca.pem")]).unwrap()),
            );
            let response = request_via_local_proxy(forwarder).await;

            // The client-visible 502 is the contract under test. The connector
            // can be dropped before its TLS alert or TCP close reaches the
            // synthetic server, so do not wait for the server handshake to
            // finish on its own.
            server.abort();
            let _ = server.await;
            pumping.store(false, Ordering::Release);
            pump.join().unwrap();

            assert!(
                response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
                "unexpected proxy response: {response:?}"
            );
            assert!(response.ends_with("target unavailable\n"));
        });
    }

    #[test]
    fn tls_handshake_timeout_is_mapped_to_gateway_timeout() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let client_ip = Ipv4Addr::new(198, 18, 12, 1);
            let server_ip = Ipv4Addr::new(198, 18, 12, 2);
            let (client_net, server_net, pumping, pump) =
                linked_userspace_nets(client_ip, server_ip);
            let target_address = SocketAddr::new(server_ip.into(), 8_445);
            let mut listener = server_net.tcp_bind(target_address).await.unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::time::sleep(Duration::from_millis(400)).await;
                drop(stream);
            });

            let target = Target::parse("https://service.example.test:8445").unwrap();
            let tcp = test_connector(
                client_net,
                client_ip,
                target.clone(),
                target_address,
                Duration::from_millis(100),
            )
            .await;
            let forwarder = HttpForwarder::new(
                tcp,
                target,
                Some(build_tls_connector(&[fixture_path("forward-ca.pem")]).unwrap()),
            );
            let response = request_via_local_proxy(forwarder).await;
            timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();

            pumping.store(false, Ordering::Release);
            pump.join().unwrap();

            assert!(
                response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"),
                "unexpected proxy response: {response:?}"
            );
            assert!(response.ends_with("target connection timed out\n"));
        });
    }
}
