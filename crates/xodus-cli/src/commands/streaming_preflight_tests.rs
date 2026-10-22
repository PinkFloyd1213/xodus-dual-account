use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn streaming_metadata_failure_returns_error_without_panic_or_touching_existing_game() {
    for response in [
        "HTTP/1.1 403 Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    ] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("game.exe"), b"existing-game").unwrap();
        std::fs::write(root.path().join("dlc.bin"), b"existing-dlc").unwrap();
        std::fs::write(
            root.path().join(".xodus-streaming.msixvc"),
            b"existing-marker",
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![];
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let client = reqwest::Client::new();
        let tokens = TokenManager::with_memory();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run(
                &client,
                &tokens,
                format!("http://{address}/?token=PRIVATE-SECRET"),
                root.path().to_string_lossy().into(),
                true,
                Some(1),
                None,
                true,
                false,
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(code, ExitCode::FAILURE);
        for (file, expected) in [
            ("game.exe", "existing-game"),
            ("dlc.bin", "existing-dlc"),
            (".xodus-streaming.msixvc", "existing-marker"),
        ] {
            assert_eq!(
                std::fs::read(root.path().join(file)).unwrap(),
                expected.as_bytes()
            );
        }
        server.await.unwrap();
    }
}
