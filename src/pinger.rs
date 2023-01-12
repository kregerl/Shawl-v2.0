use std::{
    io::{self, Cursor},
    time::Duration, fmt::{Display},
};

use serde::Deserialize;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use varint::VarintWrite;

#[derive(Debug)]
pub enum McPingServerError {
    FailedToConnect,
    NoResponse,
    PacketWriteError(io::Error),
    DeserializeResponseError(serde_json::Error),
    Timeout(tokio::time::error::Elapsed),
}

impl Display for McPingServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McPingServerError::FailedToConnect => f.write_str("Failed to connect to server"),
            McPingServerError::NoResponse => f.write_str("Not enough bytes in response"),
            McPingServerError::PacketWriteError(error) => f.write_str(&error.to_string()),
            McPingServerError::DeserializeResponseError(error) => f.write_str(&error.to_string()),
            McPingServerError::Timeout(error) => f.write_str(&format!("Connection timed out: {}", &error.to_string())),
        }   
    }
}

impl From<io::Error> for McPingServerError {
    fn from(error: io::Error) -> Self {
        McPingServerError::PacketWriteError(error)
    }
}

impl From<serde_json::Error> for McPingServerError {
    fn from(error: serde_json::Error) -> Self {
        McPingServerError::DeserializeResponseError(error)
    }
}

impl From<tokio::time::error::Elapsed> for McPingServerError {
    fn from(error: tokio::time::error::Elapsed) -> Self {
        McPingServerError::Timeout(error)
    }
}

#[derive(Debug, Deserialize)]
pub struct MinecraftStatusResponse {
    pub version: Version,
    pub description: Description,
    pub players: Players,
    pub favicon: Option<String>,
    #[serde(rename = "previewsChat")]
    pub previews_chat: Option<bool>,
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Description {
    Plain(String),
    ChatObject { text: String },
}

#[derive(Debug, Deserialize)]
pub struct Version {
    pub name: String,
    pub protocol: i32,
}

#[derive(Debug, Deserialize)]
pub struct Players {
    pub max: i32,
    pub online: i32,
    pub sample: Option<Vec<PlayerSample>>,
}

#[derive(Debug, Deserialize)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

pub async fn ping_server(
    addr: &str,
    port: u16,
    timeout: Duration,
) -> Result<MinecraftStatusResponse, McPingServerError> {
    let mut stream = TcpStream::connect(format!("{}:{}", addr, port))
        .await
        .map_err(|_| McPingServerError::FailedToConnect)?;

    let result = tokio::time::timeout(timeout, write_to_stream(&mut stream, addr, port)).await?;
    match result {
        Ok(res) => Ok(res),
        Err(error) => {
            stream.shutdown().await?;
            Err(error)
        }
    }
}

async fn write_to_stream(
    stream: &mut TcpStream,
    addr: &str,
    port: u16,
) -> Result<MinecraftStatusResponse, McPingServerError> {
    let mut buffer = Cursor::new(vec![0u8; 0]);
    buffer.write_u8(0).await?; // PacketID
    buffer.write_signed_varint_32(-1)?; // ProtocolVersion
    buffer.write_unsigned_varint_32(addr.len() as u32)?; // Address Length
    buffer.write_all(addr.as_bytes()).await?; // Address bytes
    buffer.write_all(&port.to_be_bytes()).await?; // Port
    buffer.write_unsigned_varint_32(1)?; // NextState

    stream.write_u8(buffer.get_ref().len() as u8).await?; // Write Total Packet Length to STREAM

    stream.write(buffer.get_ref()).await?; // Write rest of buffer to stream
    stream.write(&vec![1, 0]).await?; // Status Request

    stream.flush().await?;
    let mut response = vec![0; 16384];

    loop {
        // Wait for the socket to be readable
        stream.readable().await?;

        match stream.try_read(&mut response) {
            Ok(n) => {
                response.truncate(n);
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
    if response.len() <= 5 {
        return Err(McPingServerError::NoResponse);
    }
    // println!("{} :: Status: {:#?}", addr, String::from_utf8(response[5..].to_vec()));
    Ok(serde_json::from_slice(&response[5..])?)
}
