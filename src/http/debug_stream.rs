use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper stream that logs read/write events for debugging
pub struct DebugStream<S> {
    inner: S,
    id: usize,
    name: String,
    /// Data that was "unread" and should be returned before reading from inner
    buffered_data: Vec<u8>,
    /// Current position in buffered_data
    buffered_pos: usize,
}

impl<S> DebugStream<S> {
    pub fn new(inner: S, id: usize, name: String) -> Self {
        Self {
            inner,
            id,
            name,
            buffered_data: Vec::new(),
            buffered_pos: 0,
        }
    }

    /// Create a DebugStream with pre-buffered data that will be returned first
    pub fn with_buffered_data(inner: S, buffered_data: Vec<u8>, id: usize, name: String) -> Self {
        Self {
            inner,
            id,
            name,
            buffered_data,
            buffered_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DebugStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First, drain any buffered data
        if self.buffered_pos < self.buffered_data.len() {
            let buffered_pos = self.buffered_pos;
            let buffered_len = self.buffered_data.len();
            let to_copy = std::cmp::min(buffered_len - buffered_pos, buf.remaining());

            // Copy and update position before logging
            buf.put_slice(&self.buffered_data[buffered_pos..buffered_pos + to_copy]);
            self.buffered_pos = buffered_pos + to_copy;

            let glimpse = String::from_utf8_lossy(buf.filled());
            let glimpse_short = if glimpse.len() > 50 {
                &glimpse[..50]
            } else {
                &glimpse
            };
            tracing::info!(
                "[Conn {}] {} READ {} bytes (buffered): {:?}",
                self.id,
                self.name,
                to_copy,
                glimpse_short
            );

            return Poll::Ready(Ok(()));
        }

        // Normal read from inner stream
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();

        if after > before {
            let len = after - before;
            // Optional: Print glimpse of data (careful with binary)
            let data = &buf.filled()[before..after];
            let glimpse = String::from_utf8_lossy(data);
            // Truncate glimpse
            let glimpse_short = if glimpse.len() > 50 {
                &glimpse[..50]
            } else {
                &glimpse
            };
            tracing::info!(
                "[Conn {}] {} READ {} bytes: {:?}",
                self.id,
                self.name,
                len,
                glimpse_short
            );
        } else if let Poll::Ready(Ok(())) = &poll {
            // EOF usually
            // tracing::info!("[Conn {}] {} READ EOF", self.id, self.name);
        }

        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DebugStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                let data = &buf[..*n];
                if let Ok(s) = std::str::from_utf8(data) {
                    let snippet = if s.len() > 2000 { &s[..2000] } else { s };
                    tracing::info!(
                        "[Conn {}] {} WRITE {} bytes: {:?}",
                        self.id,
                        self.name,
                        n,
                        snippet
                    );
                } else {
                    tracing::info!(
                        "[Conn {}] {} WRITE {} bytes (binary)",
                        self.id,
                        self.name,
                        n
                    );
                }
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
