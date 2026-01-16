use anyhow::Result;
use bytes::Bytes;
use ocserv_rs::config::Config;
use ocserv_rs::http::handlers::{handle_request, ServerState};
use ocserv_rs::vpn::cstp::{CstpPacket, PacketType};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

async fn start_test_server() -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let listen_addr = format!("127.0.0.1:{}", addr.port());

    let mut config = Config::default();
    config.server.listen = listen_addr.clone();

    // Setup Network Config
    config.network.ipv4_pool = "10.0.0.0/24".to_string();
    config.network.dns_servers = vec!["1.1.1.1".to_string()];

    let dummy_hash = "0000000000000000000000000000000000000000".to_string();
    let state = Arc::new(ServerState::new(Arc::new(config), dummy_hash));

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = state.clone();

            // For testing we skip TLS and use direct TCP for the "encrypted" channel
            // This simplifies the test setup significantly while still testing the HTTP/Upgrade logic
            // In real app, `stream` would be `TlsStream`.

            let io = hyper_util::rt::TokioIo::new(stream);

            tokio::spawn(async move {
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req| handle_request(req, state.clone())),
                    )
                    .with_upgrades()
                    .await
                {
                    eprintln!("Error serve_connection: {:?}", e);
                }
            });
        }
    });

    Ok((listen_addr, handle))
}

#[tokio::test]
async fn test_cstp_connect_upgrade() -> Result<()> {
    let (addr, _server_handle) = start_test_server().await?;

    // 1. Connect using raw TCP
    let mut stream = tokio::net::TcpStream::connect(&addr).await?;

    // 2. Send CONNECT request
    let request = format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
         Host: {}\r\n\
         X-CSTP-Address-Type: IPv4\r\n\
         \r\n",
        addr
    );
    stream.write_all(request.as_bytes()).await?;

    // 3. Read Response Headers
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Verify 200 OK and CSTP headers
    let response_lower = response.to_lowercase();
    println!("Response received: {}", response);
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response_lower.contains("x-cstp-address: 10.10.0.100"));
    assert!(response_lower.contains("x-cstp-dns: 1.1.1.1"));

    // 4. Test Tunnel Data (KeepAlive)
    // Send KeepAlive packet
    let keepalive = CstpPacket::new(PacketType::KeepAlive, Bytes::new());
    let encoded = keepalive.encode();
    stream.write_all(&encoded).await?;

    // 5. Read Response (Should be KeepAlive echo)
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;

    let (ptype, len) = CstpPacket::parse_header(&header)?;
    assert_eq!(ptype, PacketType::KeepAlive);
    assert_eq!(len, 0);

    // 6. Test Data Packet (Should be logged)
    let data_pkt = CstpPacket::new(PacketType::Data, Bytes::from(vec![0x45, 0x00, 0x00, 0x20])); // Fake IPv4 header start
    stream.write_all(&data_pkt.encode()).await?;

    // Server doesn't echo Data packets yet, just logs them.
    // So we just ensure connection doesn't drop.

    // 7. Test Disconnect
    let disconnect = CstpPacket::new(PacketType::Disconnect, Bytes::new());
    stream.write_all(&disconnect.encode()).await?;

    // Wait for server to close?
    // ...

    Ok(())
}
