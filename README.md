**Only for educational or research purposes.**

This is a simple C2 made in Rust and has very basic features listed below:

```bash
Available commands in C2 prompt:

  <args> are required, [args] are optional
  help                             Show this menu
  shell <cmd>                      Run a local shell command
  clear                            Clear the screen
  ──────────────────────────────────────────────────────
  Commands available when a client is connected
  ──────────────────────────────────────────────────────
  list                             List active connections
  cmd <ID> <command>               Send a cmd command to a host
  psh <ID> <command>               Send a PowerShell command to a host
  spawn <ID>                       Start an interactive shell
  import-psh <ID> <file>           Import a PowerShell script into the client
  run-psh <ID> <Function>          Run a function from imported scripts
  inject <ID> <Path> <args>        Execute an EXE/DLL in memory

  upload <ID> <file> <dest>        Upload a file to a host
  download <ID> <file> <dest>      Download a file from a host
  portscan <ID> <IP> <NUM1> <NUM2> Port scan a host
  screenshot <ID>                  Take a screenshot
  keylogger <ID> on/off            Toggle keylogger
  kill <ID>                        Kill the beacon on the host
  exit                             Close all connections and exit (ctrl+d)
```

The server CLI includes colored output (`[+]` green for success, `[-]` red for disconnects, `[!]` yellow for errors), a startup banner, and a formatted connection table with timestamps when running `list`.
To build the C2, simply run `cargo build --release` in the parent folder and the binaries will be available in `target/release/`.

**Cross-compiling for Windows on Ubuntu/Debian:**

Install the MinGW-w64 toolchain and add the Rust Windows target:

```bash
sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
```

Then build with:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Binaries will be in `target/x86_64-pc-windows-gnu/release/`.

The usage is pretty straightforward.

P.S: Any issues and PRs are welcome.