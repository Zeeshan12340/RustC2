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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_shell_runs_without_panicking() {
        spawn_shell("local echo hello".to_string());
    }

    #[test]
    fn spawn_shell_handles_failing_command() {
        // A failing command should print to stderr but not panic
        spawn_shell("local false".to_string());
    }

    #[test]
    fn spawn_shell_empty_suffix_is_noop() {
        // When the command has no second word, shell_command is "" — bash -c "" exits 0
        spawn_shell("local".to_string());
    }
}
