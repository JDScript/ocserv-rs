use std::collections::HashMap;
use std::io::{self, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, trace};

/// Maximum size for HTTP headers
const MAX_HEADERS_SIZE: usize = 8192;

/// Parsed HTTP request
#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: u8, // 0 = HTTP/1.0, 1 = HTTP/1.1
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Get a header value (case-insensitive lookup)
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Parse x-www-form-urlencoded body
    pub fn parse_form(&self) -> HashMap<String, String> {
        let body = String::from_utf8_lossy(&self.body);
        body.split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next().unwrap_or("");
                Some((
                    urlencoding::decode(key).ok()?.into_owned(),
                    urlencoding::decode(value).ok()?.into_owned(),
                ))
            })
            .collect()
    }
}

/// HTTP response builder with EXACT header casing
pub struct HttpResponse {
    status_code: u16,
    status_text: String,
    headers: Vec<(String, String)>, // Preserves order and exact case
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status_code: u16, status_text: &str) -> Self {
        Self {
            status_code,
            status_text: status_text.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn ok() -> Self {
        Self::new(200, "OK")
    }

    pub fn not_found() -> Self {
        Self::new(404, "Not Found")
    }

    /// Add a header with EXACT casing preserved
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Set body content
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Set body from string
    pub fn body_str(self, body: &str) -> Self {
        self.body(body.as_bytes().to_vec())
    }

    /// Build the raw HTTP response bytes
    pub fn build(&self, http_version: u8) -> Vec<u8> {
        let mut response = Vec::new();

        // Status line
        let version = if http_version == 0 { "1.0" } else { "1.1" };
        write!(
            &mut response,
            "HTTP/{} {} {}\r\n",
            version, self.status_code, self.status_text
        )
        .unwrap();

        // Headers (with EXACT casing)
        for (name, value) in &self.headers {
            write!(&mut response, "{}: {}\r\n", name, value).unwrap();
        }

        // Content-Length if we have a body
        if !self.body.is_empty() {
            write!(&mut response, "Content-Length: {}\r\n", self.body.len()).unwrap();
        }

        // End of headers
        response.extend_from_slice(b"\r\n");

        // Body
        response.extend_from_slice(&self.body);

        response
    }
}

/// Read and parse an HTTP request from the stream
pub async fn read_request<S>(stream: &mut S) -> io::Result<Option<HttpRequest>>
where
    S: AsyncReadExt + Unpin,
{
    trace!("read_request: Starting to read HTTP request...");
    let mut buf = vec![0u8; MAX_HEADERS_SIZE];
    let mut total_read = 0;

    // Read until we find \r\n\r\n (end of headers)
    loop {
        if total_read >= MAX_HEADERS_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Headers too large",
            ));
        }

        trace!(
            "read_request: About to read from stream (total_read={})",
            total_read
        );
        let n = stream.read(&mut buf[total_read..]).await?;
        trace!("read_request: Read {} bytes", n);
        if n == 0 {
            if total_read == 0 {
                return Ok(None); // Clean EOF
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed during header read",
            ));
        }
        total_read += n;

        // Debug: Log what we received
        let data_preview = String::from_utf8_lossy(&buf[..std::cmp::min(total_read, 200)]);
        trace!(
            "read_request: Data preview (first 200 chars): {:?}",
            data_preview
        );

        // Check for end of headers
        if let Some(pos) = find_header_end(&buf[..total_read]) {
            trace!("read_request: Found header end at position {}", pos);
            // Include the full \r\n\r\n - httparse needs this to know headers are complete
            let header_bytes = &buf[..pos + 4];
            let body_start = pos + 4; // Skip \r\n\r\n

            // Parse headers
            let mut headers_buf = [httparse::EMPTY_HEADER; 64];
            let mut req = httparse::Request::new(&mut headers_buf);

            trace!(
                "read_request: Parsing {} bytes of headers (buf[..{}])",
                header_bytes.len(),
                pos + 4
            );

            match req.parse(header_bytes) {
                Ok(httparse::Status::Complete(parsed_len)) => {
                    trace!(
                        "read_request: httparse Complete, parsed {} bytes",
                        parsed_len
                    );
                    let method = req.method.unwrap_or("GET").to_string();
                    let path = req.path.unwrap_or("/").to_string();
                    let version = req.version.unwrap_or(1);

                    // Convert headers to HashMap
                    let mut headers = HashMap::new();
                    for header in req.headers.iter() {
                        let name = header.name.to_string();
                        let value = String::from_utf8_lossy(header.value).to_string();
                        headers.insert(name, value);
                    }

                    // Check Content-Length for body
                    let content_length: usize = headers
                        .iter()
                        .find(|(k, _)| k.to_lowercase() == "content-length")
                        .and_then(|(_, v)| v.parse().ok())
                        .unwrap_or(0);

                    // Read body if present
                    let mut body = Vec::new();
                    if content_length > 0 {
                        // Some body bytes may already be in our buffer
                        let already_read = total_read - body_start;
                        if already_read > 0 {
                            body.extend_from_slice(&buf[body_start..total_read]);
                        }

                        // Read remaining body bytes
                        while body.len() < content_length {
                            let mut chunk = vec![0u8; content_length - body.len()];
                            let n = stream.read(&mut chunk).await?;
                            if n == 0 {
                                break;
                            }
                            body.extend_from_slice(&chunk[..n]);
                        }
                    }

                    debug!(
                        "Parsed HTTP request: {} {} (body: {} bytes)",
                        method,
                        path,
                        body.len()
                    );

                    return Ok(Some(HttpRequest {
                        method,
                        path,
                        version,
                        headers,
                        body,
                    }));
                }
                Ok(httparse::Status::Partial) => {
                    // Need more data, continue reading
                    trace!("read_request: httparse returned Partial, need more data");
                    continue;
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("HTTP parse error: {}", e),
                    ));
                }
            }
        }
    }
}

/// Find the position of \r\n\r\n in the buffer
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Write an HTTP response to the stream
pub async fn write_response<S>(
    stream: &mut S,
    response: &HttpResponse,
    http_version: u8,
) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let bytes = response.build(http_version);

    info!(
        "Sending HTTP response: {} {} ({} bytes)",
        response.status_code,
        response.status_text,
        bytes.len()
    );

    // Log first 500 chars for debugging
    if let Ok(s) = std::str::from_utf8(&bytes) {
        let preview = if s.len() > 500 { &s[..500] } else { s };
        debug!("Response preview:\n{}", preview);
    }

    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
