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
