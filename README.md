**Only for educational or research purposes.**

This is a simple C2 made in Rust and has very basic features listed below:

```bash
Available commands in C2 prompt:

  <args> are required, [args] are optional
  help                  Show this menu
  shell <cmd>           Run a local shell command
  revshell <lang> [ip] [port]  Generate a reverse shell in specified language
       Example: `revshell bash`, `nc`,`curl`,`php`,`powershell`,`python`
  connection <raw|client> Switches between a raw or c2 client connection
       Client connection by default, toggles when run with no arguments.
  ------------------------------------------------------------- 
  Commands available when client is connected
  ------------------------------------------------------------- 
  list                      List active connections
  cmd <ID> <command>        Send a cmd command to a host
  psh <ID> <command>        Send a PowerShell command to a host
  spawn <id>                Start an interactive shell
  import-psh <ID> <file>    Import a PowerShell script into the client
  run-psh <ID> <Function>   Run a function from the imported scripts
  inject <ID> <Path> <args> Execute an EXE/DLL in memory

  upload <ID> <file> <dest>        Upload a file to a host
  download <ID> <file> <dest>      Download a file from a host
  portscan <ID> <IP> <NUM1> <NUM2> Port scan a host
  kill <ID>                        Kills the beacon on the host
  exit                             Close all connections and exit(ctrl+d)
```
To build the C2, simply run `cargo build --release` in the parent folder and the binaries will be available in `target/release/`.
The usage is pretty straightforward.

P.S: Any issues and PRs are welcome.