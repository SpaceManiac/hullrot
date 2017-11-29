use std::io::{self, Read, Write, BufRead};
use std::sync::mpsc;
use std::collections::HashMap;
use std::mem;

use mio::*;
use mio::net::*;

use openssl;
use openssl::ssl::*;
use openssl::x509;

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
                    println!("connected: {}", remote);

                    let token = Token(next_token);
                    next_token = next_token.checked_add(1).expect("token overflow");
                    poll.register(&stream, token, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();

                    let ssl = Ssl::new(&ctx).unwrap();
                    let stream = match ssl.accept(stream) {
                        Ok(stream) => Stream::Active(stream),
                        Err(HandshakeError::SetupFailure(e)) => {
                            println!("SetupFailure: {:?}", e);
                            continue;
                        }
                        Err(HandshakeError::Failure(mid)) => {
                            println!("Failure: {:?}", mid);
                            continue;
                        }
                        Err(HandshakeError::Interrupted(mid)) => Stream::Handshaking(mid),
                    };

                    clients.insert(token, Connection {
                        stream,
                        read_buf: BufReader::new(),
                        write_buf: BufWriter::new(),
                        dropped: false,
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
                        match read_packets(&mut connection.read_buf.with(stream)) {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                            Err(e) => {
                                println!("{:?}", e);
                                connection.dropped = true;
                            }
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
                    Stream::Invalid => { connection.dropped = true; break },
                    _ => break,
                };

                if !connection.write_buf.buf.is_empty() {
                    match connection.write_buf.with(stream).flush_buf() {
                        Ok(()) => {}
                        Err(e) => {
                            // TODO: store the error message nicely
                            println!("{:?}", e);
                            connection.dropped = true;
                        }
                    }
                    break;
                /*} else if let Ok(message) = connection.write_rx.try_recv() {
                    match connection.write_buf.with(stream).write_all(&message) {
                        Ok(()) => {}
                        Err(e) => {
                            connection.client.disconnected = Some(error_message(e));
                            break;
                        }
                    }*/
                } else {
                    break
                }
            }

            !connection.dropped
        })
    }
}

// ----------------------------------------------------------------------------
// Support

enum Stream {
    Invalid,
    Handshaking(MidHandshakeSslStream<TcpStream>),
    Active(SslStream<TcpStream>),
}

impl Stream {
    fn resolve(&mut self) -> Option<&mut SslStream<TcpStream>> {
        *self = match mem::replace(self, Stream::Invalid) {
            Stream::Handshaking(mid) => match mid.handshake() {
                Ok(stream) => Stream::Active(stream),
                Err(HandshakeError::SetupFailure(e)) => {
                    println!("2 SetupFailure: {:?}", e);
                    Stream::Invalid
                }
                Err(HandshakeError::Failure(mid)) => {
                    println!("2 Failure: {:?}", mid);
                    Stream::Invalid
                }
                Err(HandshakeError::Interrupted(mid)) => Stream::Handshaking(mid),
            },
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
    //write_rx: mpsc::Receiver<Packet>,
    //write_tx: mpsc::SyncSender<Packet>,
    dropped: bool,
}

fn read_packets<R: BufRead + ?Sized>(read: &mut R) -> io::Result<()> {
    use byteorder::{BigEndian, ReadBytesExt};
    use mumble_protocol::*;
    use mumble_protocol::protobuf::parse_from_bytes;

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

                match ty {
                    0 => {
                        println!("{:?}", parse_from_bytes::<Version>(&buffer[6..len]).unwrap());
                    }
                    _ => panic!("uh oh {}", ty),
                }

                consumed += len;
                buffer = &buffer[len..];
            }
        }
        read.consume(consumed);
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
