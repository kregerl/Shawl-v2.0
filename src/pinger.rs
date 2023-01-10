use std::{
    io::{self, BufReader},
    task::Poll, mem::size_of,
};

use async_minecraft_ping::StatusResponse;
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[derive(Debug)]
pub enum McPingServerError {
    FailedToConnect,
    PacketWriteError(io::Error),
}

impl From<io::Error> for McPingServerError {
    fn from(error: io::Error) -> Self {
        McPingServerError::PacketWriteError(error)
    }
}

// FIXME: Send correct bytes: 
// Implement varints. https://gist.github.com/zh32/7190955#file-serverlistping17-java-L41
pub async fn ping_server(addr: &str, port: u16) -> Result<(), McPingServerError> {
    let mut stream = TcpStream::connect(format!("{}:{}", addr, port))
        .await
        .map_err(|_| McPingServerError::FailedToConnect)?;

    let mut buffer: Vec<u8> = Vec::new();



    // buffer.write_all(b"\x13\x00\x00\x0d").await.unwrap();
    // buffer.write_all(addr.as_bytes()).await.unwrap();
    // buffer.write_all(b"\x63").await.unwrap();
    // buffer.write_all(&port.to_be_bytes().to_vec()).await.unwrap();
    // buffer.write_all(b"\x01").await.unwrap();

    let n = stream.write(&buffer).await?;
    println!("Bytes: {}", n);
    stream.write(b"\x01\x00").await?;

    let mut msg = vec![0; 1024];

    loop {
        // Wait for the socket to be readable
        stream.readable().await?;


        // Try to read data, this may still fail with `WouldBlock`
        // if the readiness event is a false positive.
        match stream.try_read(&mut msg) {
            Ok(n) => {
                msg.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    // println!("Lossy: {}", String::from_utf8_lossy(&msg));
    println!("Here: {:#?}", msg);

    for byte in msg {
        println!("Char: {}::{}", byte, String::from_utf8_lossy(&vec![byte]));
    }

    Ok(())
}
