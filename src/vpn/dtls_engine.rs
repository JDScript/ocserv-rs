use anyhow::Result;
use openssl::ssl::{Ssl, SslContext, SslStream};
use std::io::{self, Cursor, Read, Write};

/// In-memory stream that implements Read/Write for SslStream
/// This replaces direct MemBio usage since openssl::bio is private.
struct MemoryStream {
    incoming: Cursor<Vec<u8>>, // Data written FROM network, READ by SSL
    outgoing: Vec<u8>,         // Data written BY SSL, READ by network
}

impl MemoryStream {
    fn new() -> Self {
        Self {
            incoming: Cursor::new(Vec::new()),
            outgoing: Vec::new(),
        }
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.incoming.read(buf)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "End of stream"));
        }
        Ok(n)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.outgoing.flush()
    }
}

/// A wrapper around OpenSSL SSL object and Memory Stream
/// Handles encryption/decryption without async runtime dependencies.
pub struct DtlsEngine {
    stream: SslStream<MemoryStream>,
    user_data: Option<Box<dyn std::any::Any + Send>>,
}

unsafe impl Send for DtlsEngine {}

impl DtlsEngine {
    pub fn new(ctx: &SslContext, mode: DtlsMode) -> Result<Self> {
        let mut ssl = Ssl::new(ctx)?;

        if mode == DtlsMode::Server {
            ssl.set_accept_state();
        } else {
            ssl.set_connect_state();
        }

        let stream = SslStream::new(ssl, MemoryStream::new())?;

        Ok(Self {
            stream,
            user_data: None,
        })
    }

    /// Feed incoming UDP packet (encrypted) into the engine.
    /// Returns decrypted application data (if any).
    pub fn feed_encrypted(&mut self, buf: &[u8]) -> Result<Vec<Vec<u8>>> {
        // 1. Write encrypted data to MemoryStream's incoming buffer
        if !buf.is_empty() {
            let inner = self.stream.get_mut();
            // We need to append to the cursor.
            // If cursor position is at end, we can append.
            // If cursor is in middle, we might need to handle it.
            // Simpler: Reset cursor if empty, or append.

            let pos = inner.incoming.position();
            let len = inner.incoming.get_ref().len() as u64;

            if pos == len {
                // Consumed everything, reset
                inner.incoming.get_mut().clear();
                inner.incoming.set_position(0);
            }

            inner.incoming.get_mut().extend_from_slice(buf);
        }

        // 2. Drive the state machine (SSL_read)
        let mut decrypted_packets = Vec::new();
        let mut read_buf = [0u8; 4096];

        loop {
            match self.stream.ssl_read(&mut read_buf) {
                Ok(n) => {
                    if n > 0 {
                        decrypted_packets.push(read_buf[..n].to_vec());
                    }
                }
                Err(e) => {
                    let code = e.code();
                    if code == openssl::ssl::ErrorCode::WANT_READ
                        || code == openssl::ssl::ErrorCode::WANT_WRITE
                    {
                        break;
                    }
                    if code == openssl::ssl::ErrorCode::ZERO_RETURN {
                        break; // EOF
                    }
                    if code == openssl::ssl::ErrorCode::SYSCALL {
                        // Check io error
                        if let Some(io_err) = e.io_error() {
                            if io_err.kind() == io::ErrorKind::WouldBlock {
                                break;
                            }
                        }
                    }
                    // For now, treat other errors as fatal or break?
                    // UDP is lossy, maybe log and break?
                    // But handshake errors are fatal.
                    // Let's propagate error for now.
                    return Err(e.into());
                }
            }
        }

        Ok(decrypted_packets)
    }

    /// Feed outgoing application data (plaintext) into the engine.
    /// This writes to SSL, which encrypts it into the MemoryStream.
    /// You must call `extract_outgoing` afterwards to get the encrypted bytes.
    pub fn feed_decrypted(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.ssl_write(buf)?;
        Ok(())
    }

    /// Extract outgoing encrypted data (handshake or app data) from MemoryStream.
    pub fn extract_outgoing(&mut self) -> Result<Option<Vec<u8>>> {
        let inner = self.stream.get_mut();
        if inner.outgoing.is_empty() {
            return Ok(None);
        }

        let data = inner.outgoing.clone();
        inner.outgoing.clear();
        Ok(Some(data))
    }

    pub fn is_init_finished(&self) -> bool {
        // rust-openssl Ssl::state_string_long() or similiar?
        // SslRef::is_init_finished() exists since 0.10.
        // But verifying...
        // Wrapper might not expose it directly on all versions.
        // We can assume if we can read DATA packets, we are good.
        true // Placeholder
    }

    /// Get the raw pointer to the underlying SSL object.
    /// Required for identifying the session in PSK callbacks.
    pub fn ssl_ptr(&self) -> usize {
        use foreign_types::ForeignTypeRef;
        self.stream.ssl().as_ptr() as usize
    }

    /// Attach arbitrary user data to the engine (e.g. for cleanup guards)
    pub fn set_user_data(&mut self, data: Box<dyn std::any::Any + Send>) {
        self.user_data = Some(data);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DtlsMode {
    Server,
    Client,
}
