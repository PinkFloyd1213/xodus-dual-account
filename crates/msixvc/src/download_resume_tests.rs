use super::*;

#[tokio::test]
async fn streaming_resume_preserves_bytes_across_pause_and_process_restart_offset() {
    for initial_offset in [0u64, 4096] {
        let payload: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = payload.clone();
        let starts = if initial_offset == 0 {
            vec![0usize, 4096]
        } else {
            vec![4096]
        };
        let server = tokio::spawn(async move {
            for start in starts {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let byte = socket.read_u8().await.unwrap();
                    request.push(byte);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 8192);
                }
                let request = String::from_utf8(request).unwrap().to_lowercase();
                assert!(request.contains(&format!("range: bytes={start}-16383\r\n")));
                let headers = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-16383/16384\r\nConnection: close\r\n\r\n",
                    body.len() - start
                );
                socket.write_all(headers.as_bytes()).await.unwrap();
                let end = if start == 0 { 4096 } else { body.len() };
                socket.write_all(&body[start..end]).await.unwrap();
            }
        });
        let (control, pause) = tokio::sync::watch::channel(false);
        let (checkpoints, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let resume = control.clone();
        let restarter = tokio::spawn(async move {
            if initial_offset == 0 {
                assert_eq!(observed.recv().await, Some(4096));
                resume.send(false).unwrap();
            }
        });
        let mut output = payload[..initial_offset as usize].to_vec();
        let file = SegmentFile {
            offset: 0,
            length: 16384,
            data_hashs: vec![],
            keep_encrypted: false,
        };
        let mut did_pause = initial_offset != 0;
        let client = reqwest::Client::new();
        let url = format!("http://{address}/package");
        let transfer = XvdFile::download_segment_http(
            &[],
            &client,
            &url,
            &mut output,
            &file,
            [0; 32],
            |position, _| {
                if !did_pause && position == 4096 {
                    did_pause = true;
                    control.send(true).unwrap();
                }
            },
            Some(pause),
            initial_offset,
            |position| {
                checkpoints.send(position).ok();
                Ok(())
            },
        );
        timeout(tokio::time::Duration::from_secs(5), transfer)
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        restarter.await.unwrap();
        assert_eq!(output, payload);
    }
}
