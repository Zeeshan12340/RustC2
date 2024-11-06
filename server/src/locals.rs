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