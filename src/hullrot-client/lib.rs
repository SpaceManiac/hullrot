/*
Hullrot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hullrot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Hullrot.  If not, see <http://www.gnu.org/licenses/>.
*/

//! The foreign-function interface for hosting and updating state within BYOND.
extern crate byteorder;
extern crate libc;
extern crate mio;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

extern crate hullrot_common;

use libc::{c_char, c_int};
use std::cell::RefCell;
use std::io::{self, BufRead, Write};
use std::sync::mpsc;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mio::net::*;
use mio::*;
use serde::Serialize;

// ----------------------------------------------------------------------------
// Foreign function interface

thread_local!(static OUTPUT_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) });
thread_local!(static HANDLE: RefCell<Option<Handle>> = const { RefCell::new(None) });

fn with_output_buffer<F: FnOnce(&mut Vec<u8>)>(f: F) -> *const c_char {
    OUTPUT_BUFFER.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        f(&mut buf);
        buf.push(0);
        buf.as_ptr() as *const c_char
    })
}

fn json_write<T: Serialize + ?Sized>(buf: &mut Vec<u8>, t: &T) {
    if let Err(e) = serde_json::to_writer(&mut *buf, t) {
        buf.clear();
        let _ = write!(buf, r#"{{"error":{:?}}}"#, e.to_string());
    }
}

fn json_response<T: Serialize + ?Sized>(t: &T) -> *const c_char {
    with_output_buffer(|buf| json_write(buf, t))
}

fn error<T: AsRef<str>>(msg: T) -> *const c_char {
    #[derive(Serialize)]
    struct Error<'a> {
        error: &'a str,
    }
    json_response(&Error {
        error: msg.as_ref(),
    })
}

fn ok() -> *const c_char {
    b"{}\0".as_ptr() as *const c_char
}

fn with_handle<F: FnOnce(&mut Handle) -> *const c_char>(f: F) -> *const c_char {
    HANDLE.with(|cell| match cell.try_borrow_mut() {
        Ok(mut opt) => match *opt {
            Some(ref mut handle) => f(handle),
            None => error("not initialized"),
        },
        Err(_) => error("context crashed"),
    })
}

#[allow(dead_code)]
unsafe fn parse_args<'a>(argc: &'a c_int, argv: &'a *const *const c_char) -> Vec<&'a [u8]> {
    let mut args = Vec::new();
    for i in 0..*argc as isize {
        args.push(std::ffi::CStr::from_ptr(*argv.offset(i)).to_bytes());
    }
    args
}

macro_rules! function {
    ($name:ident($($args:ident)*) $body:block) => {
        #[no_mangle]
        pub extern fn $name(_argc: c_int, _argv: *const *const c_char) -> *const c_char {
            $(let $args = unsafe { &parse_args(&_argc, &_argv)[..] };)*
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
        major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0),
        minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0),
        patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0),
    })
}}

function! { hullrot_init(args) {
    HANDLE.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_some() {
            return error("already initialized");
        }

        let addr = match args.first() {
            None => "127.0.0.1:10961",
            Some(addr) => match std::str::from_utf8(addr) {
                Ok(addr) => addr,
                Err(_) => return error("non-utf8 server address"),
            }
        };

        match Handle::init(addr) {
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
    fn init(addr: &str) -> Result<Handle, String> {
        let init = init_control(addr).map_err(|e| e.to_string())?;
        let (control_tx, control_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let thread = std::thread::spawn(|| control_thread(init, control_rx, event_tx));
        Ok(Handle {
            thread,
            tx: control_tx,
            rx: event_rx,
        })
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

fn init_control(addr: &str) -> Result<Init, Box<dyn std::error::Error>> {
    let poll = Poll::new()?;
    let addr = addr.parse()?;
    let mut stream = TcpStream::connect(addr)?;
    poll.registry()
        .register(&mut stream, CLIENT, Interest::READABLE | Interest::WRITABLE)?;
    Ok(Init { poll, stream })
}

fn control_thread(
    init: Init,
    control_rx: mpsc::Receiver<Vec<u8>>,
    event_tx: mpsc::Sender<Vec<u8>>,
) {
    let Init {
        mut poll,
        mut stream,
    } = init;
    let mut events = Events::with_capacity(1024);

    let mut read_buf = hullrot_common::BufReader::new();
    let mut write_buf = hullrot_common::BufWriter::new();

    'main: loop {
        if let Err(e) = poll.poll(&mut events, Some(std::time::Duration::from_millis(5))) {
            return control_fatal(&event_tx, &e.to_string());
        }

        // Check readiness events
        for event in events.iter() {
            if event.is_writable() {
                write_buf.mark_writable();
            }
            if event.is_readable() {
                match read_packets(&mut read_buf.with(&mut stream), &event_tx) {
                    Ok(()) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
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
    json_write(&mut buf, &Error { Fatal: text });
    let _ = event_tx.send(buf);
}

fn read_packets<R: BufRead + ?Sized>(
    read: &mut R,
    event_tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let mut consumed = 0;
        {
            let mut buffer = read.fill_buf()?;
            if buffer.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            // 4 bytes length followed by json
            while buffer.len() >= 4 {
                let len = 4 + (&buffer[..]).read_u32::<BigEndian>()? as usize;
                if buffer.len() < len {
                    break; // incomplete
                }
                let _ = event_tx.send(buffer[4..len].to_owned());
                consumed += len;
                buffer = &buffer[len..];
            }
        }
        read.consume(consumed);
    }
}
