use sysinfo::System;
use std::process::exit;
use std::time::{Instant, SystemTime, Duration};
use std::thread::sleep;

#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
use winapi::um::debugapi::IsDebuggerPresent;

pub fn check_memory_limit() {
    let mut system = System::new_all();
    system.refresh_memory();

    let total_memory = system.total_memory(); // in kilobytes
    // Heuristic: If total memory is unusually low, suspect sandboxing
    if total_memory < 4_000_000_000 { // Less than 512MB
        println!("Program is likely running in a sandboxed environment.");
        exit(1);
    } 
}

pub fn sleep_evasion(sleep_duration: Duration) {
    let start_instant = Instant::now();
    let start_system_time = SystemTime::now();

    sleep(sleep_duration);

    let elapsed_instant = start_instant.elapsed();
    let elapsed_system_time = SystemTime::now()
        .duration_since(start_system_time)
        .unwrap_or_default();

    if elapsed_instant < sleep_duration || elapsed_system_time < sleep_duration {
        println!("Detected sandbox time manipulation!");
        exit(1);
    }
}

#[cfg(windows)]
pub fn check_debugger() {
    unsafe {
        if IsDebuggerPresent() != 0 {
            println!("Debugger detected! Exiting program.");
            exit(1);
        }
    }
}

