//! The foreign-function interface for hosting and updating state within BYOND.

use std::cell::RefCell;
use libc::{c_int, c_char};

use serde::Serialize;

thread_local!(static OUTPUT_BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new()));

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

unsafe fn parse_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a str> {
    let mut args = Vec::new();
    for i in 0..argc as isize {
        let cstr = ::std::ffi::CStr::from_ptr(*argv.offset(i));
        match cstr.to_str() {
            Ok(s) => args.push(s),
            Err(e) => args.push(::std::str::from_utf8(&cstr.to_bytes()[..e.valid_up_to()]).unwrap()),
        }
    }
    args
}

macro_rules! function {
    ($name:ident($args:ident) $body:block) => {
        #[no_mangle]
        pub unsafe extern fn $name(argc: c_int, argv: *const *const c_char) -> *const c_char {
            let $args = &parse_args(argc, argv)[..];
            $body
        }
    }
}

function! { hullrot_version(_args) {
    #[derive(Serialize)]
    struct Version {
        version: &'static str,
    }

    json_response(&Version { version: env!("CARGO_PKG_VERSION") })
}}
