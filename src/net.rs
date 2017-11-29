use std::io::{self, Read, Write, BufRead};
use std::sync::mpsc;
use std::collections::HashMap;
use std::mem;

use mio::*;
use mio::net::*;

use openssl::ssl::*;
use openssl::x509;

use mumble_protocol::Packet;
use Client;

// ----------------------------------------------------------------------------
// Main server thread

pub fn server_thread() {
    const SERVER: Token = Token(0);

    // TODO: audit
    let mut ctx = SslContext::builder(SslMethod::tls()).expect("failed: create ssl context");
    ctx.set_cipher_list("AES256-SHA").unwrap();
    ctx.set_verify(SSL_VERIFY_NONE);
    ctx.set_certificate_file("cert.pem", x509::X509_FILETYPE_PEM).expect("failed: load server certificate");
    ctx.set_private_key_file("key.pem", x509::X509_FILETYPE_PEM).expect("failed: load server private key");
    ctx.check_private_key().expect("failed: private key validation");
    let ctx = ctx.build();

    let poll = Poll::new().unwrap();
    let addr = "0.0.0.0:64738".parse().unwrap();
    let server = TcpListener::bind(&addr).unwrap();
    poll.register(&server, SERVER, Ready::readable(), PollOpt::edge()).unwrap();

    let mut next_token = 1;
    let mut clients = HashMap::new();
    let mut events = Events::with_capacity(1024);

    loop {
        poll.poll(&mut events, Some(::std::time::Duration::from_millis(10))).unwrap();

        // Check readiness events
        for event in events.iter() {
            if event.token() == SERVER {
                // Accept connections until we get a WouldBlock
                loop {
                    let (stream, remote) = match server.accept() {
                        Ok(r) => r,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("{:?}", e),
                    };
                    println!("({}) connected", remote);

                    let token = Token(next_token);
                    next_token = next_token.checked_add(1).expect("token overflow");
                    poll.register(&stream, token, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();

                    let ssl = Ssl::new(&ctx).unwrap();
                    let stream = Stream::new(ssl.accept(stream));

                    let (tx, rx) = mpsc::channel();
                    clients.insert(token, Connection {
                        stream,
                        read_buf: BufReader::new(),
                        write_buf: BufWriter::new(),
                        write_rx: rx,
                        //write_tx: tx.clone(),
                        client: Client::new(remote, PacketChannel(tx)),
                    });
                }
            } else {
                let connection = clients.get_mut(&event.token()).unwrap();
                let readiness = event.readiness();
                if readiness.is_writable() {
                    connection.write_buf.writable = true;
                }
                if readiness.is_readable() {
                    if let Some(stream) = connection.stream.resolve() {
                        match read_packets(&mut connection.read_buf.with(stream), &mut connection.client) {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                            Err(e) => io_error(&mut connection.client, e),
                        }
                    }
                }
            }
        }

        // Flush pending writes and drop disconnectors
        clients.retain(|_, connection| {
            while connection.write_buf.writable {
                connection.stream.resolve();
                let stream = match connection.stream {
                    Stream::Active(ref mut stream) => stream,
                    Stream::Invalid => {
                        kick(&mut connection.client, "SSL setup failure".to_owned());
                        break
                    },
                    _ => break,
                };

                if !connection.write_buf.buf.is_empty() {
                    match connection.write_buf.with(stream).flush_buf() {
                        Ok(()) => {}
                        Err(e) => io_error(&mut connection.client, e),
                    }
                    break;
                } else if let Ok(message) = connection.write_rx.try_recv() {
                    match message {
                        ::mumble_protocol::Packet::Ping(_) => {}
                        _ => println!("--> {:?}", message),
                    }
                    let encoded = match message.encode() {
                        Ok(v) => v,
                        Err(e) => { kick(&mut connection.client, format!("Encode error: {}", e)); break }
                    };
                    match connection.write_buf.with(stream).write_all(&encoded) {
                        Ok(()) => {}
                        Err(e) => { io_error(&mut connection.client, e); break }
                    }
                } else {
                    break
                }
            }

            if let Some(ref message) = connection.client.disconnected {
                println!("{} quit: {}", connection.client, message);
                false
            } else {
                true
            }
        })
    }
}

// ----------------------------------------------------------------------------
// Support

#[derive(Clone, Debug)]
pub struct PacketChannel(mpsc::Sender<Packet>);

impl PacketChannel {
    #[inline]
    pub fn send<T: Into<Packet>>(&self, message: T) -> bool {
        self.0.send(message.into()).is_ok()
    }

    /*#[inline]
    pub fn try_send<T: Into<Packet>>(&self, message: T) -> Result<(), mpsc::TrySendError<Packet>> {
        self.0.try_send(message.into())
    }*/
}

enum Stream {
    Invalid,
    Handshaking(MidHandshakeSslStream<TcpStream>),
    Active(SslStream<TcpStream>),
}

impl Stream {
    fn new(res: Result<SslStream<TcpStream>, HandshakeError<TcpStream>>) -> Stream {
        match res {
            Ok(stream) => Stream::Active(stream),
            Err(HandshakeError::SetupFailure(e)) => {
                println!("SetupFailure: {:?}", e);
                Stream::Invalid
            }
            Err(HandshakeError::Failure(mid)) => {
                println!("Failure: {:?}", mid);
                Stream::Invalid
            }
            Err(HandshakeError::Interrupted(mid)) => Stream::Handshaking(mid),
        }
    }

    fn resolve(&mut self) -> Option<&mut SslStream<TcpStream>> {
        *self = match mem::replace(self, Stream::Invalid) {
            Stream::Handshaking(mid) => Stream::new(mid.handshake()),
            other => other,
        };
        match *self {
            Stream::Active(ref mut stream) => Some(stream),
            _ => None,
        }
    }
}

struct Connection {
    stream: Stream,
    read_buf: BufReader,
    write_buf: BufWriter,
    write_rx: mpsc::Receiver<Packet>,
    //write_tx: mpsc::SyncSender<Packet>,
    client: Client,
}

fn kick(c: &mut Client, why: String) {
    if c.disconnected.is_none() {
        c.disconnected = Some(why);
    }
}

fn io_error(c: &mut Client, e: io::Error) {
    use std::io::ErrorKind::*;
    kick(c, if [ConnectionAborted, ConnectionReset, UnexpectedEof].contains(&e.kind()) {
        "Disconnected".to_owned()
    } else {
        e.to_string()
    })
}

fn read_packets<R: BufRead + ?Sized, H: Handler>(read: &mut R, handler: &mut H) -> io::Result<()> {
    use byteorder::{BigEndian, ReadBytesExt};
    use mumble_protocol::*;

    loop {
        let mut consumed = 0;
        {
            let mut buffer = read.fill_buf()?;
            if buffer.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            // 2 bytes type, 4 bytes length, followed by encoded protobuf
            while buffer.len() >= 6 {
                let ty = (&buffer[..2]).read_u16::<BigEndian>().unwrap();
                let len = 6 + (&buffer[2..6]).read_u32::<BigEndian>().unwrap() as usize;
                if buffer.len() < len {
                    break;  // incomplete
                }
                if let Err(e) = handler.handle(Packet::parse(ty, &buffer[6..len])?) {
                    return handler.error(e);
                }
                consumed += len;
                buffer = &buffer[len..];
            }
        }
        read.consume(consumed);
    }
}

pub trait Handler {
    type Error;
    fn handle(&mut self, packet: Packet) -> Result<(), Self::Error>;
    fn error(&mut self, _error: Self::Error) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "Internal server error"))
    }
}

// ----------------------------------------------------------------------------
// I/O helpers

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// Reimplementation of a `BufReader` which does not own its inner stream.
struct BufReader {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl BufReader {
    pub fn new() -> BufReader {
        BufReader::with_capacity(DEFAULT_BUF_SIZE)
    }

    pub fn with_capacity(cap: usize) -> BufReader {
        BufReader {
            buf: vec![0; cap].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    pub fn with<'b, 'r, R: ?Sized>(&'b mut self, read: &'r mut R) -> BufReaderWith<'b, 'r, R> {
        BufReaderWith { buf: self, inner: read }
    }
}

struct BufReaderWith<'b, 'r, R: ?Sized + 'r> {
    buf: &'b mut BufReader,
    inner: &'r mut R,
}

impl<'b, 'r, R: Read + ?Sized + 'r> Read for BufReaderWith<'b, 'r, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we don't have any buffered data and we're doing a massive read
        // (larger than our internal buffer), bypass our internal buffer
        // entirely.
        if self.buf.pos == self.buf.cap && buf.len() >= self.buf.buf.len() {
            return self.inner.read(buf);
        }
        let nread = {
            let mut rem = self.fill_buf()?;
            rem.read(buf)?
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<'b, 'r, R: Read + ?Sized + 'r> BufRead for BufReaderWith<'b, 'r, R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // If we've reached the end of our internal buffer then we need to fetch
        // some more data from the underlying reader.
        // Branch using `>=` instead of the more correct `==`
        // to tell the compiler that the pos..cap slice is always valid.
        if self.buf.pos >= self.buf.cap {
            debug_assert!(self.buf.pos == self.buf.cap);
            self.buf.cap = self.inner.read(&mut self.buf.buf)?;
            self.buf.pos = 0;
        }
        Ok(&self.buf.buf[self.buf.pos..self.buf.cap])
    }

    fn consume(&mut self, amt: usize) {
        self.buf.pos = ::std::cmp::min(self.buf.pos + amt, self.buf.cap);
    }
}

/// Reimplementation of a `BufWriter` which does not own its inner stream,
/// and handles `WouldBlock` errors appropriately.
struct BufWriter {
    buf: Vec<u8>,
    cap: usize,
    writable: bool,
}

impl BufWriter {
    pub fn new() -> BufWriter {
        BufWriter::with_capacity(DEFAULT_BUF_SIZE)
    }

    pub fn with_capacity(cap: usize) -> BufWriter {
        BufWriter {
            buf: Vec::with_capacity(cap),
            cap: cap,
            writable: false,
        }
    }

    pub fn with<'b, 'w, W: Write + ?Sized>(&'b mut self, write: &'w mut W) -> BufWriterWith<'b, 'w, W> {
        BufWriterWith {
            buf: self,
            inner: write,
        }
    }
}

struct BufWriterWith<'b, 'w, W: Write + ?Sized + 'w> {
    buf: &'b mut BufWriter,
    inner: &'w mut W,
}

impl<'b, 'w, W: Write + ?Sized + 'w> BufWriterWith<'b, 'w, W> {
    fn flush_buf(&mut self) -> io::Result<()> {
        let mut written = 0;
        let len = self.buf.buf.len();
        let mut ret = Ok(());
        if len == 0 { return ret }
        //println!("flush_buf({})", len);
        while written < len {
            let r = self.inner.write(&self.buf.buf[written..]);
            //println!("write: {:?}", r);
            match r {
                Ok(0) => {
                    ret = Err(io::ErrorKind::WriteZero.into());
                    break;
                }
                Ok(n) => written += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.buf.writable = false;
                    break;
                }
                Err(e) => { ret = Err(e); break }
            }
        }
        if written > 0 {
            self.buf.buf.drain(..written);
        }
        ret
    }
}

impl<'b, 'w, W: Write + ?Sized + 'w> Write for BufWriterWith<'b, 'w, W> {
    // If this succeeds, it will always succeed with the correct length. The
    // input will always be written either out or to the buffer. If a given
    // write would have returned `WouldBlock`, the `writable` flag is unset and
    // `Ok` is returned.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // If we would go over capacity, flush our buffer first.
        // Use `cap` rather than `buf.capacity()` because we allow `buf` to
        // grow beyond its initial capacity in order to store oversized writes.
        if self.buf.buf.len() + buf.len() > self.buf.cap {
            self.flush_buf()?;
        }
        // Our buffer will have been completely flushed if there's been no
        // `WouldBlock`. In that case, a big write gets written now.
        if buf.len() >= self.buf.buf.capacity() && self.buf.buf.len() == 0 {
            match self.inner.write(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    Write::write(&mut self.buf.buf, buf)
                }
                other => other
            }
        } else {
            Write::write(&mut self.buf.buf, buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buf().and_then(|()| self.inner.flush())
    }
}
