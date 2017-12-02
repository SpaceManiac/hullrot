// Server-side implementation of the Mumble protocol, documented online:
// https://mumble-protocol.readthedocs.io/en/latest/overview.html

use std::io::{self, Read, Write, BufRead};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::collections::{HashMap, VecDeque};
use std::mem;

use mio::*;
use mio::net::*;

use openssl::ssl::*;
use openssl::x509;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use mumble_protocol::Packet;
use opus::{Channels, Application, Bitrate, Decoder, Encoder};
use Client;

// ----------------------------------------------------------------------------
// Main server thread

const TCP_SERVER: Token = Token(0);
const CONTROL_SERVER: Token = Token(1);
const CONTROL_CHANNEL: Token = Token(2);
//const UDP_SOCKET: Token = Token(3);
const FIRST_TOKEN: u32 = 3;

pub struct Init {
    ctx: SslContext,
    poll: Poll,
    server: TcpListener,
    control_server: TcpListener,
}

pub fn init_server() -> Result<Init, Box<::std::error::Error>> {
    // TODO: audit
    let mut ctx = SslContext::builder(SslMethod::tls())?;
    ctx.set_cipher_list("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
        ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:\
        DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA")?;
    ctx.set_verify(SSL_VERIFY_NONE);
    ctx.set_certificate_file("data/hullrot/cert.pem", x509::X509_FILETYPE_PEM)?;
    ctx.set_private_key_file("data/hullrot/key.pem", x509::X509_FILETYPE_PEM)?;
    ctx.check_private_key()?;
    let ctx = ctx.build();

    let poll = Poll::new()?;
    let addr = "0.0.0.0:64738".parse()?;
    let server = TcpListener::bind(&addr)?;
    poll.register(&server, TCP_SERVER, Ready::readable(), PollOpt::edge())?;

    /*let udp = UdpSocket::bind(&addr).unwrap();
    poll.register(&udp, UDP_SOCKET, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();
    let mut udp_writable = true;*/

    let addr = "127.0.0.1:10961".parse()?;  // accept local control connections only
    let control_server = TcpListener::bind(&addr)?;
    poll.register(&control_server, CONTROL_SERVER, Ready::readable(), PollOpt::edge())?;

    Ok(Init { ctx, poll, server, control_server })
}

pub fn server_thread(init: Init) {
    let Init { ctx, poll, server, control_server } = init;
    let mut udp_buf = [0u8; 1024];  // Mumble protocol says this is the packet size limit

    let mut clients = HashMap::new();
    let mut events = Events::with_capacity(1024);
    let mut next_token: u32 = FIRST_TOKEN;

    let mut control_client: Option<ControlConnection> = None;

    loop {
        poll.poll(&mut events, Some(::std::time::Duration::from_millis(5))).unwrap();

        // Check readiness events
        for event in events.iter() {
            if event.token() == TCP_SERVER {
                // Accept connections until we get a WouldBlock
                loop {
                    let (stream, remote) = match server.accept() {
                        Ok(r) => r,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => { println!("{:?}", e); continue },
                    };
                    println!("({}) connected", remote);

                    let session = next_token;
                    let token = Token(session as usize);
                    next_token = next_token.checked_add(1).expect("token overflow");
                    poll.register(&stream, token, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();

                    let ssl = Ssl::new(&ctx).unwrap();
                    let stream = Stream::new(ssl.accept(stream));
                    clients.insert(token, new_connection(session, remote, stream));
                }
            } else if event.token() == CONTROL_SERVER {
                loop {
                    let (stream, remote) = match control_server.accept() {
                        Ok(r) => r,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => { println!("{:?}", e); continue },
                    };
                    if !is_loopback(&remote) {
                        println!("CONTROL: {} rejected", remote);
                    }
                    if let Some(old) = control_client.take() {
                        println!("CONTROL: dropping previous");
                        poll.deregister(&old.stream).unwrap();
                    }
                    println!("CONTROL: {} connected", remote);
                    poll.register(&stream, CONTROL_CHANNEL, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();
                    control_client = Some(ControlConnection {
                        stream,
                        read_buf: BufReader::new(),
                        write_buf: BufWriter::new(),
                        read_queue: VecDeque::new(),
                        write_queue: VecDeque::new(),
                        dead: false,
                    });
                }
            } else if event.token() == CONTROL_CHANNEL {
                if let Some(ref mut control) = control_client {
                    let readiness = event.readiness();
                    if readiness.is_writable() {
                        control.write_buf.writable = true;
                    }
                    if readiness.is_readable() {
                        match control.read() {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                            Err(e) => {
                                println!("CONTROL: disconnected: {}", e);
                                control.dead = true;
                                break
                            }
                        }
                    }
                }
            /*} else if event.token() == UDP_SOCKET {
                let readiness = event.readiness();
                if readiness.is_readable() {
                    loop {
                        let (len, remote) = match udp.recv_from(&mut udp_buf[..]) {
                            Ok(r) => r,
                            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => { println!("{:?}", e); continue },
                        };
                        let buf = &udp_buf[..len];
                        println!("Got datagram, len = {}", len);
                    }
                }
                if readiness.is_writable() {
                    udp_writeable = true;
                }*/
            } else {
                let connection = clients.get_mut(&event.token()).unwrap();
                let readiness = event.readiness();
                if readiness.is_writable() {
                    connection.write_buf.writable = true;
                }
                if readiness.is_readable() {
                    if let Some(stream) = connection.stream.resolve() {
                        match read_packets(&mut connection.read_buf.with(stream), &mut connection.client, &mut connection.decoder) {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                            Err(e) => io_error(&mut connection.client, e),
                        }
                    }
                }
            }
        }

        // Update the control channel
        let mut dead = false;
        if let Some(ref mut control) = control_client {
            while control.write_buf.writable {
                if !control.write_buf.buf.is_empty() {
                    match control.write_buf.with(&mut control.stream).flush_buf() {
                        Ok(()) => {}
                        Err(e) => { println!("CONTROL: flush error: {:?}", e); }
                    }
                    break;
                } else if let Some(event) = control.write_queue.pop_front() {
                    let vec = match ::serde_json::to_vec(&event) {
                        Ok(vec) => vec,
                        Err(e) => { println!("CONTROL: serialize error: {:?}", e); break; }
                    };
                    assert!(vec.len() <= 0xffffffff);
                    let mut out = control.write_buf.with(&mut control.stream);
                    match (|| {
                        out.write_u32::<BigEndian>(vec.len() as u32)?;
                        out.write_all(&vec)
                    })() {
                        Ok(()) => {}
                        Err(e) => { println!("CONTROL: write error: {:?}", e); break; }
                    }
                } else {
                    break
                }
            }
            dead = control.dead;
        }
        // Drop the control channel if it needs to be
        if dead {
            control_client = None;
        }

        {
            // This elaborate construction is used to let us tick() clients and
            // still give them a reference to the other clients.
            let mut clients_vec: Vec<&mut Connection> = clients.values_mut().collect();
            for i in 0..clients_vec.len() {
                let (before, after) = clients_vec.split_at_mut(i);
                let (connection, after) = after.split_first_mut().unwrap();  // should be infallible

                // Read events happened above, so tick immediately
                connection.client.tick(EveryoneElse(before, after));
            }

            // Now that clients have ticked, flush pending writes and finalize disconnectors
            for i in 0..clients_vec.len() {
                let (before, after) = clients_vec.split_at_mut(i);
                let (connection, after) = after.split_first_mut().unwrap();  // should be infallible

                while connection.write_buf.writable {
                    connection.stream.resolve();
                    let stream = match connection.stream {
                        Stream::Active(ref mut stream) => stream,
                        Stream::Invalid => {
                            connection.client.kick("SSL setup failure");
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
                    } else if let Ok(command) = connection.write_rx.try_recv() {
                        match command {
                            Command::Packet(packet) => {
                                match packet {
                                    Packet::Ping(_) => {}
                                    _ => println!("OUT: {:?}", packet)
                                }
                                let encoded = match packet.encode() {
                                    Ok(v) => v,
                                    Err(e) => { connection.client.kick(format!("Encode error: {}", e)); break }
                                };
                                match connection.write_buf.with(stream).write_all(&encoded) {
                                    Ok(()) => {}
                                    Err(e) => { io_error(&mut connection.client, e); break }
                                }
                            }
                            Command::VoiceData { who, seq, audio } => {
                                // Encode the audio
                                let len = connection.encoder.encode(&audio, &mut udp_buf).unwrap();

                                // Construct the UDPTunnel packet
                                let mut encoded = Vec::new();
                                let _ = encoded.write_u16::<BigEndian>(1);  // UDP tunnel
                                let _ = encoded.write_u32::<BigEndian>(0);  // Placeholder for length

                                // Construct the voice datagram
                                let start = encoded.len();
                                let _ = encoded.write_u8(128);  // header byte, opus on normal channel
                                let _ = write_varint(&mut encoded, who as i64);  // session of source user
                                let _ = write_varint(&mut encoded, seq);  // sequence number
                                let _ = write_varint(&mut encoded, len as i64);  // opus header
                                let total_len = encoded.len() + len - start;
                                let _ = (&mut encoded[2..6]).write_u32::<BigEndian>(total_len as u32);

                                //println!("OUT: voice: who={} seq={} audio={} tiny={} big={}", who, seq, audio.len(), len, total_len);

                                let mut out = connection.write_buf.with(stream);
                                match (|| {
                                    out.write_all(&encoded)?;
                                    out.write_all(&udp_buf[..len])
                                })() {
                                    Ok(()) => {}
                                    Err(e) => { io_error(&mut connection.client, e); break }
                                }
                            }
                        }
                    } else {
                        break
                    }
                }

                // should run in lockstep, but separate for lifetime reasons
                if connection.client.disconnected.is_some() {
                    connection.client.quit(EveryoneElse(before, after));
                }
                if let Some(ref message) = connection.client.disconnected {
                    println!("{} quit: {}", connection.client, message);
                    if let Some(tcp) = connection.stream.inner() {
                        poll.deregister(tcp).unwrap();
                    }
                }
            }
        }

        // Drop disconnectors from the map
        clients.retain(|_, connection| connection.client.disconnected.is_none());
    }
}

fn new_connection(session: u32, remote: SocketAddr, stream: Stream) -> Connection {
    let (tx, rx) = mpsc::channel();
    let decoder = Decoder::new(SAMPLE_RATE, CHANNELS).unwrap();
    let mut encoder = Encoder::new(SAMPLE_RATE, CHANNELS, APPLICATION).unwrap();
    encoder.set_bitrate(BITRATE).unwrap();
    encoder.set_vbr(false).unwrap();
    Connection {
        stream,
        encoder,
        decoder,
        read_buf: BufReader::new(),
        write_buf: BufWriter::new(),
        write_rx: rx,
        //write_tx: tx.clone(),
        client: Client::new(remote, PacketChannel(tx), session),
    }
}

pub fn is_loopback(remote: &SocketAddr) -> bool {
    match *remote {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

// ----------------------------------------------------------------------------
// Support

const SAMPLE_RATE: u32 = 48000;
const CHANNELS: Channels = Channels::Mono;
const APPLICATION: Application = Application::Voip;
const BITRATE: Bitrate = Bitrate::Bits(40000);
pub type Sample = i16;

#[derive(Clone, Debug)]
pub struct PacketChannel(mpsc::Sender<Command>);

pub enum Command {
    Packet(Packet),
    VoiceData {
        who: u32,
        seq: i64,
        audio: Vec<Sample>,
    },
}

impl PacketChannel {
    #[inline]
    pub fn send<T: Into<Packet>>(&self, message: T) -> bool {
        self.0.send(Command::Packet(message.into())).is_ok()
    }

    #[inline]
    pub fn send_voice(&self, who: u32, seq: i64, audio: Vec<Sample>) -> bool {
        self.0.send(Command::VoiceData { who, seq, audio }).is_ok()
    }
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

    fn inner(&mut self) -> Option<&mut TcpStream> {
        match *self {
            Stream::Invalid => None,
            Stream::Handshaking(ref mut mid) => Some(mid.get_mut()),
            Stream::Active(ref mut ssl) => Some(ssl.get_mut()),
        }
    }
}

struct Connection {
    stream: Stream,
    read_buf: BufReader,
    write_buf: BufWriter,
    write_rx: mpsc::Receiver<Command>,
    //write_tx: mpsc::SyncSender<Packet>,
    client: Client,
    decoder: Decoder,
    encoder: Encoder,
}

fn io_error(c: &mut Client, e: io::Error) {
    use std::io::ErrorKind::*;
    if [ConnectionAborted, ConnectionReset, UnexpectedEof].contains(&e.kind()) {
        c.kick("Disconnected")
    } else {
        c.kick(e.to_string())
    }
}

pub struct EveryoneElse<'a, 'b: 'a>(&'a mut [&'b mut Connection], &'a mut [&'b mut Connection]);

impl<'a, 'b> EveryoneElse<'a, 'b> {
    pub fn for_each<F: FnMut(&mut Client)>(&mut self, mut f: F) {
        for each in self.0.iter_mut() {
            f(&mut each.client);
        }
        for each in self.1.iter_mut() {
            f(&mut each.client);
        }
    }
}

// ----------------------------------------------------------------------------
// Protocol implementation

fn read_packets<R: BufRead + ?Sized>(read: &mut R, client: &mut Client, decoder: &mut Decoder) -> io::Result<()> {
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
                if ty == 1 {  // UdpTunnel
                    read_voice(&buffer[6..len], client, decoder)?;
                } else {
                    let packet = Packet::parse(ty, &buffer[6..len])?;
                    // handle pings immediately, save Client the trouble
                    if let Packet::Ping(ref ping) = packet {
                        client.sender.send(packet! { Ping;
                            set_timestamp: ping.get_timestamp(),
                        });
                    } else {
                        println!("IN: {:?}", packet);
                    }
                    client.events.push_back(Command::Packet(packet));
                }
                consumed += len;
                buffer = &buffer[len..];
            }
        }
        read.consume(consumed);
    }
}

fn read_voice(mut buffer: &[u8], client: &mut Client, decoder: &mut Decoder) -> io::Result<()> {
    //const CELT_ALPHA: u8 = 0;
    const PING: u8 = 1;
    //const SPEEX: u8 = 2;
    //const CELT_BETA: u8 = 3;
    const OPUS: u8 = 4;
    const TARGET_NORMAL: u8 = 0;
    //const TARGET_LOOPBACK: u8 = 31;

    let header = buffer.read_u8()?;
    let (ty, target) = (header >> 5, header & 0b11111);
    if ty == PING {
        let timestamp = read_varint(&mut buffer)?;
        println!("Ping: {}", timestamp);
        return Ok(())
    } else if ty != OPUS {
        println!("Unknown type: {}", ty);
        return Ok(())
    }
    if target != TARGET_NORMAL {
        println!("Unknown target: {}", target);
    }

    // incoming format
    let sequence_number = read_varint(&mut buffer)?;
    let mut opus_length = read_varint(&mut buffer)? & 0x3fff;
    let terminator = opus_length & 0x2000 != 0;
    if terminator {
        opus_length &= 0x1fff;
    }
    let opus_packet = &buffer[..opus_length as usize];

    let mut output = [0i16; 960 * 2];
    let len = decoder.decode(opus_packet, &mut output, false).unwrap();

    /*println!("IN: voice: seq={} rem={} enc={} dec={}",
        sequence_number,
        buffer.len() - opus_length as usize,
        opus_length,
        len,
        );*/

    client.events.push_back(Command::VoiceData {
        who: 0,
        seq: sequence_number,
        audio: output[..len].to_owned(),
    });
    Ok(())
}

// https://mumble-protocol.readthedocs.io/en/latest/voice_data.html#variable-length-integer-encoding
#[inline]
fn read_varint<R: Read>(r: &mut R) -> io::Result<i64> {
    read_varint_inner(r, false)
}

fn read_varint_inner<R: Read>(r: &mut R, recursive: bool) -> io::Result<i64> {
    let first_byte = r.read_u8()? as i64;
    if first_byte & 128 == 0 {  // 7-bit positive number
        Ok(first_byte & 127)
    } else if first_byte & 64 == 0 {  // 14-bit positive number
        let second_byte = r.read_u8()? as i64;
        Ok(((first_byte & 63) << 8) | second_byte)
    } else if first_byte & 32 == 0 {  // 21-bit positive number
        let second_byte = r.read_u8()? as i64;
        let third_byte = r.read_u8()? as i64;
        Ok(((first_byte & 31) << 16) | (second_byte << 8) | third_byte)
    } else if first_byte & 16 == 0 {  // 28-bit positive number
        let second_byte = r.read_u8()? as i64;
        let third_byte = r.read_u8()? as i64;
        let fourth_byte = r.read_u8()? as i64;
        Ok(((first_byte & 15) << 24) | (second_byte << 16) | (third_byte << 8) | fourth_byte)
    } else if first_byte & 12 == 0 {  // 32-bit positive number
        Ok(r.read_u32::<BigEndian>()? as i64)
    } else if first_byte & 12 == 4 {  // 64-bit number
        r.read_i64::<BigEndian>()
    } else if first_byte & 12 == 8 {  // negative recursive varint
        if recursive {  // can't negate a negation
            Err(io::ErrorKind::InvalidData.into())
        } else {
            read_varint_inner(r, true).map(|i| -i)
        }
    } else /* first_byte & 12 == 4 */ {  // byte-inverted negative two-bit number
        Ok(!(first_byte & 3))
    }
}

fn write_varint<W: Write>(w: &mut W, mut val: i64) -> io::Result<()> {
    if val < 0 {  // negative
        if val >= -4 {  // small value
            return w.write_u8(0b11111100 | (!val as u8));
        } else if val < -0xffffffff {  // large negative value
            w.write_u8(0b11110100)?;  // 64-bit number
            return w.write_i64::<BigEndian>(val);
        } else {
            w.write_u8(0b11111000)?;  // negative recursive varint
            val = -val;
        }
    }
    // positive
    if val < (1 << 7) {  // 7-bit positive number
        w.write_u8(val as u8)
    } else if val < (1 << 14) {  // 14-bit positive number
        w.write_u8(0b10000000 | (val >> 8) as u8)?;
        w.write_u8(val as u8)
    } else if val < (1 << 21) {  // 21-bit positive number
        w.write_u8(0b11000000 | (val >> 16) as u8)?;
        w.write_u8((val >> 8) as u8)?;
        w.write_u8(val as u8)
    } else if val < (1 << 28) {  // 28-bit positive number
        w.write_u8(0b11100000 | (val >> 24) as u8)?;
        w.write_u8((val >> 16) as u8)?;
        w.write_u8((val >> 8) as u8)?;
        w.write_u8(val as u8)
    } else if val < (1 << 32) {  // 32-bit positive number
        w.write_u8(0b11110000)?;
        w.write_u32::<BigEndian>(val as u32)
    } else {
        w.write_u8(0b11110100)?;  // 64-bit number
        w.write_i64::<BigEndian>(val)
    }
}

#[test]
pub fn test_varint_agreement() {
    let mut buf = [0u8; 16];
    for i in -1000..1000 {
        write_varint(&mut &mut buf[..], i).unwrap();
        assert_eq!(read_varint(&mut &buf[..]).unwrap(), i);
    }
}

// ----------------------------------------------------------------------------
// Control protocol

struct ControlConnection {
    stream: TcpStream,
    read_buf: BufReader,
    write_buf: BufWriter,
    write_queue: VecDeque<ControlOut>,
    read_queue: VecDeque<ControlIn>,
    dead: bool,
}

impl ControlConnection {
    fn read(&mut self) -> io::Result<()> {
        let mut read = self.read_buf.with(&mut self.stream);
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
                    if let Ok(msg) = ::serde_json::from_slice::<ControlIn>(&buffer[4..len]) {
                        println!("CONTROL IN: {:?}", msg);
                        self.read_queue.push_back(msg);
                    }
                    consumed += len;
                    buffer = &buffer[len..];
                }
            }
            read.consume(consumed);
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
enum ControlIn {
    Debug(String),
}

#[derive(Serialize, Debug, Clone)]
enum ControlOut {
    Debug(String),
}

// ----------------------------------------------------------------------------
// Buffered I/O helpers

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
