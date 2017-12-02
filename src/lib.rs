//! The foreign-function interface for hosting and updating state within BYOND.
extern crate libc;
extern crate mio;
extern crate byteorder;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

use std::cell::RefCell;
use std::sync::mpsc;
use std::{thread, time};
use libc::{c_int, c_char};

use serde::Serialize;

// ----------------------------------------------------------------------------
// Foreign function interface

thread_local!(static OUTPUT_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new()));
thread_local!(static HANDLE: RefCell<Option<Handle>> = RefCell::new(None));

fn with_output_buffer<F: FnOnce(&mut Vec<u8>)>(f: F) -> *const c_char {
    OUTPUT_BUFFER.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        f(&mut buf);
        buf.push(0);
        buf.as_ptr() as *const c_char
    })
}

fn json_response<T: Serialize + ?Sized>(t: &T) -> *const c_char {
    with_output_buffer(|buf| {
        if let Err(e) = ::serde_json::to_writer(&mut *buf, t) {
            use std::io::Write;
            buf.clear();
            let _ = write!(buf, r#"{{"error":{:?}}} "#, e.to_string());
        }
    })
}

fn error<T: AsRef<str>>(msg: T) -> *const c_char {
    #[derive(Serialize)]
    struct Error<'a> {
        error: &'a str,
    }
    json_response(&Error { error: msg.as_ref() })
}

fn ok() -> *const c_char {
    #[derive(Serialize)]
    struct Empty {}
    json_response(&Empty {})
}

fn with_handle<F: FnOnce(&mut Handle) -> *const c_char>(f: F) -> *const c_char {
    HANDLE.with(|cell| {
        match cell.try_borrow_mut() {
            Ok(mut opt) => match *opt {
                Some(ref mut handle) => f(handle),
                None => error("not initialized"),
            },
            Err(_) => error("context crashed"),
        }
    })
}

#[allow(dead_code)]
unsafe fn parse_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a [u8]> {
    let mut args = Vec::new();
    for i in 0..argc as isize {
        args.push(::std::ffi::CStr::from_ptr(*argv.offset(i)).to_bytes());
    }
    args
}

macro_rules! function {
    ($name:ident($($args:ident)*) $body:block) => {
        #[no_mangle]
        pub unsafe extern fn $name(_argc: c_int, _argv: *const *const c_char) -> *const c_char {
            $(let $args = &parse_args(_argc, _argv)[..];)*
            $body
        }
    }
}

function! { hullrot_dll_version() {
    #[derive(Serialize)]
    struct Version {
        version: &'static str,
        major: u32,
        minor: u32,
        patch: u32,
    }
    json_response(&Version {
        version: env!("CARGO_PKG_VERSION"),
        major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
        minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
        patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
    })
}}

function! { hullrot_init() {
    HANDLE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_some() {
            return error("already initialized");
        }
        match Handle::init() {
            Ok(handle) => {
                *opt = Some(handle);
                ok()
            },
            Err(why) => error(why),
        }
    })
}}

function! { hullrot_control(args) {
    with_handle(|handle| {
        for arg in args {
            handle.tx.send(arg.to_vec());
        }
        ok()
    })
}}

function! { hullrot_stop() {
    HANDLE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if let Some(handle) = opt.take() {
            handle.stop();
        }
        ok()
    })
}}

// ----------------------------------------------------------------------------
// Control protocol client

/// A handle to a running Hullrot server.
struct Handle {
    thread: std::thread::JoinHandle<()>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl Handle {
    /// Attempt to initialize and spawn the server in its child thread.
    fn init() -> Result<Handle, String> {
        //let (tx, rx) = mpsc::channel();
        Err("Not implemented".into())
    }

    /// Block until the server stops or crashes.
    fn stop(self) {
        drop(self.tx);
        let _ = self.thread.join();
    }
}
