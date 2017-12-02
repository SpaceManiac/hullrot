//! The foreign-function interface for hosting and updating state within BYOND.
extern crate libc;
extern crate mio;
extern crate byteorder;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

pub mod util;

use std::cell::RefCell;
use std::sync::mpsc;
use std::io::{self, Write, BufRead};
use libc::{c_int, c_char};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mio::*;
use mio::net::*;
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
        if let Err(e) = serde_json::to_writer(&mut *buf, t) {
            buf.clear();
            let _ = write!(buf, r#"{{"error":{:?}}}"#, e.to_string());
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
    b"{}\0".as_ptr() as *const c_char
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
                // return the first event, should either be a Fatal or a Version
                let msg = match handle.rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(msg) => msg,
                    Err(_) => return error("server did not respond in time"),
                };
                *opt = Some(handle);
                with_output_buffer(|buf| buf.extend_from_slice(&msg))
            },
            Err(why) => error(why),
        }
    })
}}

function! { hullrot_control(args) {
    with_handle(|handle| {
        for arg in args {
            if handle.tx.send(arg.to_vec()).is_err() {
                return error("network thread panicked");
            }
        }

        with_output_buffer(|buf| {
            buf.push(b'[');
            let mut first = true;
            while let Ok(value) = handle.rx.try_recv() {
                if !first {
                    buf.push(b',');
                }
                buf.extend_from_slice(&value);
                first = false;
            }
            buf.push(b']');
        })
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

const CLIENT: Token = Token(0);

/// A handle to a running Hullrot server.
struct Handle {
    thread: std::thread::JoinHandle<()>,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Handle {
    /// Attempt to initialize and spawn the server in its child thread.
    fn init() -> Result<Handle, String> {
        let init = init_control().map_err(|e| e.to_string())?;
        let (control_tx, control_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let thread = std::thread::spawn(|| control_thread(init, control_rx, event_tx));
        Ok(Handle { thread, tx: control_tx, rx: event_rx })
    }

    /// Stop the network thread and block until it finishes or crashes.
    fn stop(self) {
        drop(self.tx);
        drop(self.rx);
        let _ = self.thread.join();
    }
}

struct Init {
    poll: Poll,
    stream: TcpStream,
}

fn init_control() -> Result<Init, Box<::std::error::Error>> {
    let poll = Poll::new()?;
    let addr = "127.0.0.1:10961".parse()?;
    let stream = TcpStream::connect(&addr)?;
    poll.register(&stream, CLIENT, Ready::readable() | Ready::writable(), PollOpt::edge())?;
    Ok(Init { poll, stream })
}

fn control_thread(init: Init, control_rx: mpsc::Receiver<Vec<u8>>, event_tx: mpsc::Sender<Vec<u8>>) {
    let Init { poll, mut stream } = init;
    let mut events = Events::with_capacity(1024);

    let mut read_buf = util::BufReader::new();
    let mut write_buf = util::BufWriter::new();

    'main: loop {
        if let Err(e) = poll.poll(&mut events, Some(::std::time::Duration::from_millis(5))) {
            return control_fatal(&event_tx, &e.to_string());
        }

        // Check readiness events
        for event in events.iter() {
            let readiness = event.readiness();
            if readiness.is_writable() {
                write_buf.mark_writable();
            }
            if readiness.is_readable() {
                match read_packets(&mut read_buf.with(&mut stream), &event_tx) {
                    Ok(()) => {},
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                    Err(e) => return control_fatal(&event_tx, &e.to_string()),
                }
            }
        }

        // Write as needed
        while write_buf.is_writable() {
            if !write_buf.is_empty() {
                match write_buf.with(&mut stream).flush_buf() {
                    Ok(()) => {}
                    Err(e) => return control_fatal(&event_tx, &e.to_string()),
                }
                break;
            }

            match control_rx.try_recv() {
                // Write control messages as long as we can
                Ok(vec) => {
                    assert!(vec.len() <= 0xffffffff);
                    let mut out = write_buf.with(&mut stream);
                    match (|| {
                        out.write_u32::<BigEndian>(vec.len() as u32)?;
                        out.write_all(&vec)
                    })() {
                        Ok(()) => {}
                        Err(e) => return control_fatal(&event_tx, &e.to_string()),
                    }
                }
                // If there's none to send, try again later
                Err(mpsc::TryRecvError::Empty) => break,
                // The channel has dropped, we need to end quick
                Err(mpsc::TryRecvError::Disconnected) => break 'main,
            }
        }
    }

    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn control_fatal(event_tx: &mpsc::Sender<Vec<u8>>, text: &str) {
    #[derive(Serialize)]
    #[allow(non_snake_case)]
    struct Error<'a> {
        Fatal: &'a str,
    }

    let mut buf = Vec::new();
    if let Err(e) = serde_json::to_writer(&mut buf, &Error { Fatal: text }) {
        buf.clear();
        let _ = write!(buf, r#"{{"error":{:?}}}"#, e.to_string());
    }
    let _ = event_tx.send(buf);
}

fn read_packets<R: BufRead + ?Sized>(read: &mut R, event_tx: &mpsc::Sender<Vec<u8>>) -> io::Result<()> {
    loop {
        let mut consumed = 0;
        {
            let mut buffer = read.fill_buf()?;
            if buffer.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            // 4 bytes length followed by json
            while buffer.len() >= 4 {
                let len = 4 + (&buffer[..]).read_u32::<BigEndian>().unwrap() as usize;
                if buffer.len() < len {
                    break;  // incomplete
                }
                let _ = event_tx.send(buffer[4..len].to_owned());
                consumed += len;
                buffer = &buffer[len..];
            }
        }
        read.consume(consumed);
    }
}
