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

// Server-side implementation of the Mumble protocol, documented online:
// https://mumble-protocol.readthedocs.io/en/latest/overview.html

use std::io::{self, Read, Write, BufRead};
use std::net::SocketAddr;
use std::sync::mpsc;
use std::rc::Rc;
use std::collections::{HashMap, VecDeque};
use std::mem;
use std::fs;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mio::*;
use mio::net::*;
use openssl::ssl::*;
use opus::{Channels, Application, Bitrate, Decoder, Encoder};

use mumble_protocol::Packet;
use hullrot_common::{BufReader, BufWriter};
use config::Config;
use {Client, Server, ControlIn};

// ----------------------------------------------------------------------------
// Main server thread

const TCP_SERVER: Token = Token(0);
const CONTROL_SERVER: Token = Token(1);
const CONTROL_CHANNEL: Token = Token(2);
const UDP_SOCKET: Token = Token(3);
const FIRST_TOKEN: u32 = 4;

pub struct Init {
    ctx: SslContext,
    poll: Poll,
    server: TcpListener,
    control_server: TcpListener,
    udp: UdpSocket,
}

pub fn init_server(config: &Config) -> Result<Init, Box<dyn (::std::error::Error)>> {
    // TODO: audit
    let mut ctx = SslContext::builder(SslMethod::tls())?;
    ctx.set_cipher_list("EECDH+AESGCM:EDH+aRSA+AESGCM:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA")?;
    if config.auth_db.is_some() {
        ctx.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _store_ctx| {
            // Seems like a terrible idea, but apparently how Murmur behaves?
            true
        });
    }

    if fs::metadata(&config.cert_pem).is_err() && fs::metadata(&config.key_pem).is_err() {
        create_self_signed_cert(&config.cert_pem, &config.key_pem)?;
    }

    println!("Loading {}", config.cert_pem);
    ctx.set_certificate_chain_file(&config.cert_pem)?;
    println!("Loading {}", config.key_pem);
    ctx.set_private_key_file(&config.key_pem, SslFiletype::PEM)?;
    ctx.check_private_key()?;
    let ctx = ctx.build();

    let poll = Poll::new()?;
    let addr = config.mumble_addr.parse()?;
    println!("Binding tcp/{}", addr);
    let server = TcpListener::bind(&addr)?;
    poll.register(&server, TCP_SERVER, Ready::readable(), PollOpt::edge())?;

    println!("Binding udp/{}", addr);
    let udp = UdpSocket::bind(&addr).unwrap();
    poll.register(&udp, UDP_SOCKET, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();

    let addr = config.control_addr.parse()?;
    println!("Binding tcp/{}", addr);
    let control_server = TcpListener::bind(&addr)?;
    poll.register(&control_server, CONTROL_SERVER, Ready::readable(), PollOpt::edge())?;

    Ok(Init { ctx, poll, server, control_server, udp })
}

#[deny(unused_must_use)]
fn create_self_signed_cert(cert_pem: &str, key_pem: &str) -> Result<(), Box<dyn (::std::error::Error)>> {
    use openssl::x509::*;
    use openssl::x509::extension::*;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;

    // openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
    println!("Creating default self-signed certificate");

    // random private key
    let privkey = PKey::from_rsa(Rsa::generate(4096)?)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    // random serial number
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    builder.set_serial_number(&serial_number)?;
    // dummy subject name
    let subject_name = {
        let mut subject_name = X509NameBuilder::new()?;
        subject_name.append_entry_by_text("C", "US")?;
        subject_name.append_entry_by_text("ST", "CA")?;
        subject_name.append_entry_by_text("O", "Hullrot server")?;
        subject_name.append_entry_by_text("CN", "www.example.com")?;
        subject_name.build()
    };
    builder.set_subject_name(&subject_name)?;
    builder.set_pubkey(&privkey)?;

    // valid for 365 days
    let not_before = Asn1Time::days_from_now(0)?;
    builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_after(&not_after)?;

    builder.append_extension(BasicConstraints::new().build()?)?;

    // self-signed
    builder.sign(&privkey, MessageDigest::sha256())?;

    // save to file
    let cert = builder.build();
    fs::File::create(cert_pem)?.write_all(&cert.to_pem()?)?;
    fs::File::create(key_pem)?.write_all(&privkey.private_key_to_pem_pkcs8()?)?;

    Ok(())
}

pub fn server_thread(init: Init, config: &Config) {
    let Init { ctx, poll, server, control_server, udp } = init;
    let mut encode_buf = vec![0u8; 1024]; // Docs say this could go up to 0x7fffff (8MiB - 1B) in size
    let mut udp_buf = [0u8; 1024];  // Mumble protocol says this is the packet size limit
    let mut udp_crypt_buf = [0u8; 1024];
    let mut udp_writeable = true;
    let mut udp_out_queue = VecDeque::new();

    let mut clients = HashMap::new();
    let mut udp_clients = HashMap::new();
    let mut events = Events::with_capacity(1024);
    let mut next_token: u32 = FIRST_TOKEN;

    let mut control = Server::new(config);
    let mut control_client: Option<ControlConnection> = None;

    println!("Started");
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
                    clients.insert(token, Connection::new(config, session, remote, stream));
                }
            } else if event.token() == CONTROL_SERVER {
                loop {
                    let (stream, remote) = match control_server.accept() {
                        Ok(r) => r,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => { println!("{:?}", e); continue },
                    };
                    if !remote.ip().is_loopback() {
                        println!("CONTROL: {} rejected", remote);
                    }
                    if let Some(old) = control_client.take() {
                        println!("CONTROL: dropping previous");
                        poll.deregister(&old.stream).unwrap();
                    }
                    println!("CONTROL: {} connected", remote);
                    poll.register(&stream, CONTROL_CHANNEL, Ready::readable() | Ready::writable(), PollOpt::edge()).unwrap();
                    control.connect();
                    control_client = Some(ControlConnection::new(stream));
                }
            } else if event.token() == CONTROL_CHANNEL {
                if let Some(ref mut control_client) = control_client {
                    let readiness = event.readiness();
                    if readiness.is_writable() {
                        control_client.write_buf.mark_writable();
                    }
                    if readiness.is_readable() {
                        match control_client.read(&mut control.read_queue) {
                            Ok(()) => {},
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {},
                            Err(e) => {
                                println!("CONTROL: disconnected: {}", e);
                                control_client.dead = true;
                                break
                            }
                        }
                    }
                }
            } else if event.token() == UDP_SOCKET {
                let readiness = event.readiness();
                while readiness.is_readable() {
                    let (len, remote) = match udp.recv_from(&mut udp_buf[..]) {
                        Ok(r) => r,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => { println!("{:?}", e); continue },
                    };
                    let buf = &udp_buf[..len];

                    if let Err(e) = (|| -> Result<(), io::Error> {
                        if buf.len() < 4 {
                            // Just throw it away.
                            return Ok(());
                        }
                        // Four zeros _might_ still be an encrypted packet with
                        // incredibly low probability, but I don't see a better
                        // way to check.
                        if &buf[0..4] == b"\0\0\0\0" {
                            // Server list ping packet.
                            let ident = (&buf[4..]).read_u64::<BigEndian>()?;
                            let mut output = Vec::with_capacity(20);
                            // version: 1.3.0
                            output.write_u8(0)?;
                            output.write_u8(1)?;
                            output.write_u8(3)?;
                            output.write_u8(0)?;
                            // write back the ident
                            output.write_u64::<BigEndian>(ident)?;
                            // currently connected users count
                            output.write_u32::<BigEndian>(clients.len() as u32)?;
                            // maximum user count
                            output.write_u32::<BigEndian>(100)?;
                            // allowed bandwidth
                            output.write_u32::<BigEndian>(64_000)?;
                            udp_out_queue.push_back((remote, output));
                        } else {
                            // Encrypted UDP packet.
                            if let Some(connection_key) = udp_clients.get(&remote).copied() {
                                if let Some(connection) = clients.get_mut(&connection_key) {
                                    if let Some(crypt) = connection.client.crypt_state.as_mut() {
                                        let decrypted = &mut udp_crypt_buf[..buf.len() - 4];
                                        if crypt.decrypt(&buf, decrypted) {
                                            read_voice(decrypted, &mut connection.client, &mut connection.decoder, true)?;
                                        }
                                    }
                                }
                            } else {
                                // Seems insane but this is what Murmur does.
                                for (k, connection) in clients.iter_mut() {
                                    if let Some(crypt) = connection.client.crypt_state.as_mut() {
                                        let decrypted = &mut udp_crypt_buf[..buf.len() - 4];
                                        if crypt.decrypt(&buf, decrypted) {
                                            connection.udp_remote = Some(remote.clone());
                                            udp_clients.insert(remote, k.clone());
                                            read_voice(decrypted, &mut connection.client, &mut connection.decoder, true)?;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        Ok(())
                    })() {
                        println!("UDP in error: {:?}", e);
                    }
                }
                if readiness.is_writable() {
                    udp_writeable = true;
                }
            } else {
                let connection = clients.get_mut(&event.token()).unwrap();
                let readiness = event.readiness();
                if readiness.is_writable() {
                    connection.write_buf.mark_writable();
                }
                if readiness.is_readable() {
                    if let Some(stream) = connection.stream.resolve() {
                        if !connection.hash_delivered {
                            connection.hash_delivered = true;
                            let hash = stream.ssl().peer_certificate()
                                // Murmur uses SHA-1 so we shall too
                                .and_then(|cert| cert.digest(::openssl::hash::MessageDigest::sha1()).ok())
                                .map(|digest| {
                                    let mut buf = String::new();
                                    for byte in digest.iter() {
                                        use std::fmt::Write;
                                        let _ = write!(buf, "{:02x}", byte);
                                    }
                                    buf
                                });
                            connection.client.events.push_back(Command::CertHash(hash));
                        }
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
        if let Some(ref mut control_client) = control_client {
            while control_client.write_buf.is_writable() {
                if !control_client.write_buf.is_empty() {
                    match control_client.write_buf.with(&mut control_client.stream).flush_buf() {
                        Ok(()) => {}
                        Err(e) => { println!("CONTROL: flush error: {:?}", e); }
                    }
                    break;
                } else if let Some(event) = control.write_queue.pop_front() {
                    if config.verbose_control {
                        println!("CONTROL OUT: {:?}", event);
                    }
                    let vec = match ::serde_json::to_vec(&event) {
                        Ok(vec) => vec,
                        Err(e) => { println!("CONTROL: serialize error: {:?}", e); break; }
                    };
                    assert!(vec.len() <= 0xffffffff);
                    let mut out = control_client.write_buf.with(&mut control_client.stream);
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
            dead = control_client.dead;
        }
        // Drop the control channel if it needs to be
        if dead {
            control.disconnect();
            control_client = None;
        }

        {
            // This elaborate construction is used to let us tick() clients and
            // still give them a reference to the other clients.
            let mut clients_vec: Vec<&mut Connection> = clients.values_mut().collect();

            control.tick(Everyone(&mut clients_vec[..], &mut []));

            for i in 0..clients_vec.len() {
                let (before, after) = clients_vec.split_at_mut(i);
                let (connection, after) = after.split_first_mut().unwrap();  // should be infallible

                // Read events happened above, so tick immediately
                connection.client.tick(&mut control, Everyone(before, after));
            }

            // Now that clients have ticked, flush pending writes and finalize disconnectors
            for i in 0..clients_vec.len() {
                let (before, after) = clients_vec.split_at_mut(i);
                let (connection, after) = after.split_first_mut().unwrap();  // should be infallible

                while connection.write_buf.is_writable() {
                    connection.stream.resolve();
                    let stream = match connection.stream {
                        Stream::Active(ref mut stream) => stream,
                        Stream::Invalid => {
                            connection.client.kick("SSL setup failure");
                            break
                        },
                        _ => break,
                    };

                    if !connection.write_buf.is_empty() {
                        match connection.write_buf.with(stream).flush_buf() {
                            Ok(()) => {}
                            Err(e) => io_error(&mut connection.client, e),
                        }
                        break;
                    } else if let Ok(command) = connection.write_rx.try_recv() {
                        match command {
                            OutCommand::Packet(packet) => {
                                let len = packet.compute_size();
                                if len > encode_buf.len() {
                                    encode_buf.resize(len, 0);
                                }

                                if let Err(e) = packet.encode(&mut encode_buf[..len]) {
                                    connection.client.kick(format!("Encode error: {}", e));
                                    break;
                                }

                                match connection.write_buf.with(stream).write_all(&encode_buf[..len]) {
                                    Ok(()) => {}
                                    Err(e) => { io_error(&mut connection.client, e); break }
                                }
                            },
                            OutCommand::VoiceData { who, seq, audio, end } => {
                                // Encode the audio
                                let len = connection.encoders.entry(who)
                                    .or_insert_with(|| {
                                        let mut encoder = Encoder::new(SAMPLE_RATE, CHANNELS, APPLICATION).unwrap();
                                        encoder.set_bitrate(BITRATE).unwrap();
                                        encoder.set_vbr(false).unwrap();
                                        encoder
                                    })
                                    .encode(&audio, &mut udp_buf).unwrap();

                                // Construct the UDPTunnel packet
                                let mut encoded = Vec::new();
                                let _ = encoded.write_u16::<BigEndian>(1);  // UDP tunnel
                                let _ = encoded.write_u32::<BigEndian>(0);  // Placeholder for length

                                // Construct the voice datagram
                                let start = encoded.len();
                                let _ = encoded.write_u8(128);  // header byte, opus on normal channel
                                let _ = write_varint(&mut encoded, who as i64);  // session of source user
                                let _ = write_varint(&mut encoded, seq);  // sequence number
                                let _ = write_varint(&mut encoded, (len | if end { 0x2000 } else { 0 }) as i64);  // opus header
                                let total_len = encoded.len() + len - start;
                                let _ = (&mut encoded[2..6]).write_u32::<BigEndian>(total_len as u32);

                                //println!("OUT: voice: who={} seq={} audio={} tiny={} big={} end={}", who, seq, audio.len(), len, total_len, end);

                                let mut out = connection.write_buf.with(stream);
                                match (|| {
                                    out.write_all(&encoded)?;
                                    out.write_all(&udp_buf[..len])
                                })() {
                                    Ok(()) => {}
                                    Err(e) => { io_error(&mut connection.client, e); break }
                                }
                            },
                            OutCommand::VoicePing(_) => {
                                // TODO
                            },
                        }
                    } else {
                        break
                    }
                }

                // disconnect those who should be disconnected
                if let Some(message) = connection.client.disconnected.take() {
                    println!("{} quit: {}", connection.client, message);
                    connection.client.disconnected = Some(message);  // for quit() and the drop at the end
                    connection.client.quit(&mut control, Everyone(before, after));
                    if let Some(tcp) = connection.stream.inner() {
                        poll.deregister(tcp).unwrap();
                    }
                }
            }
        }

        // Drop disconnectors from the map
        clients.retain(|_, connection| connection.client.disconnected.is_none());

        // Handle UDP writes
        while udp_writeable {
            if let Some((remote, packet)) = udp_out_queue.pop_front() {
                match udp.send_to(&packet, &remote) {
                    Ok(_) => {},
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        udp_writeable = false;
                        break;
                    }
                    Err(e) => { println!("UDP out error: {:?}", e); continue },
                }
            } else {
                break
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Support

const SAMPLE_RATE: u32 = 48000;
const CHANNELS: Channels = Channels::Mono;
const APPLICATION: Application = Application::Voip;
const BITRATE: Bitrate = Bitrate::Bits(64_000);
pub type Sample = i16;

#[derive(Debug)]
pub enum Command {
    AuthCkey(String),
    CertHash(Option<String>),
    Packet(Packet),
    VoiceData {
        seq: i64,
        audio: Rc<[Sample]>,
        end: bool,
    },
}

#[derive(Clone, Debug)]
pub struct PacketChannel(mpsc::Sender<OutCommand>);

#[derive(Debug)]
enum OutCommand {
    Packet(Packet),
    VoicePing(i64),
    VoiceData {
        who: u32,
        seq: i64,
        audio: Rc<[Sample]>,
        end: bool,
    },
}

impl PacketChannel {
    #[inline]
    pub fn send<T: Into<Packet>>(&self, message: T) -> bool {
        self.0.send(OutCommand::Packet(message.into())).is_ok()
    }

    #[inline]
    pub fn send_voice(&self, who: u32, seq: i64, audio: Rc<[Sample]>) -> bool {
        self.0.send(OutCommand::VoiceData { who, seq, audio, end: false }).is_ok()
    }

    fn send_voice_ping(&self, timestamp: i64) -> bool {
        self.0.send(OutCommand::VoicePing(timestamp)).is_ok()
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
            Err(HandshakeError::WouldBlock(mid)) => Stream::Handshaking(mid),
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

struct Connection<'cfg> {
    stream: Stream,
    hash_delivered: bool,
    read_buf: BufReader,
    write_buf: BufWriter,
    write_rx: mpsc::Receiver<OutCommand>,
    client: Client<'cfg>,
    decoder: Decoder,
    encoders: HashMap<u32, Encoder>,
    udp_remote: Option<SocketAddr>,
}

impl<'cfg> Connection<'cfg> {
    fn new(config: &'cfg Config, session: u32, remote: SocketAddr, stream: Stream) -> Connection {
        let (tx, rx) = mpsc::channel();
        let decoder = Decoder::new(SAMPLE_RATE, CHANNELS).unwrap();
        Connection {
            stream,
            hash_delivered: false,
            decoder,
            encoders: HashMap::new(),
            read_buf: BufReader::new(),
            write_buf: BufWriter::new(),
            write_rx: rx,
            client: Client::new(config, remote, PacketChannel(tx), session),
            udp_remote: None,
        }
    }
}

fn io_error(c: &mut Client, e: io::Error) {
    use std::io::ErrorKind::*;
    if [ConnectionAborted, ConnectionReset, UnexpectedEof].contains(&e.kind()) {
        c.kick("Disconnected")
    } else {
        c.kick(e.to_string())
    }
}

pub struct Everyone<'a, 'b: 'a, 'cfg: 'b>(&'a mut [&'b mut Connection<'cfg>], &'a mut [&'b mut Connection<'cfg>]);

impl<'a, 'b, 'cfg> Everyone<'a, 'b, 'cfg> {
    pub fn for_each<F: FnMut(&mut Client)>(&mut self, mut f: F) {
        for each in self.0.iter_mut() {
            f(&mut each.client);
        }
        for each in self.1.iter_mut() {
            f(&mut each.client);
        }
    }

    pub fn reborrow<'c>(&'c mut self) -> Everyone<'c, 'b, 'cfg> {
        Everyone(self.0, self.1)
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
                    read_voice(&buffer[6..len], client, decoder, false)?;
                } else {
                    let packet = Packet::parse(ty, &buffer[6..len])?;
                    // handle pings immediately, save Client the trouble
                    if let Packet::Ping(ref ping) = packet {
                        client.sender.send(packet! { Ping;
                            set_timestamp: ping.get_timestamp(),
                        });
                    } else {
                        //println!("IN: {:?}", packet);
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

fn read_voice(mut buffer: &[u8], client: &mut Client, decoder: &mut Decoder, set_udp_valid: bool) -> io::Result<()> {
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
        client.sender.send_voice_ping(timestamp);
        return Ok(())
    } else if ty != OPUS {
        println!("Unknown type: {}", ty);
        return Ok(())
    }
    if target != TARGET_NORMAL {
        println!("Unknown target: {}", target);
    }

    client.udp_valid = set_udp_valid;

    // incoming format
    let sequence_number = read_varint(&mut buffer)?;
    let mut opus_length = read_varint(&mut buffer)? & 0x3fff;
    let terminator = opus_length & 0x2000 != 0;
    if terminator {
        opus_length &= 0x1fff;
    }
    let opus_packet = &buffer[..opus_length as usize];

    let mut output = [0i16; 960 * 4];
    let len = match decoder.decode(opus_packet, &mut output, false) {
        Ok(len) => len,
        Err(e) => {
            println!("DECODE ERROR: {}: {:?}", client, e);
            return Ok(());
        }
    };

    /*println!("IN: voice: seq={} rem={} enc={} dec={}",
        sequence_number,
        buffer.len() - opus_length as usize,
        opus_length,
        len,
        );*/

    client.events.push_back(Command::VoiceData {
        seq: sequence_number,
        audio: Rc::from(&output[..len]),
        end: terminator,
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
    dead: bool,
}

impl ControlConnection {
    fn new(stream: TcpStream) -> ControlConnection {
        ControlConnection {
            stream,
            read_buf: BufReader::new(),
            write_buf: BufWriter::new(),
            dead: false,
        }
    }

    fn read(&mut self, read_queue: &mut VecDeque<ControlIn>) -> io::Result<()> {
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
                    match ::serde_json::from_slice::<ControlIn>(&buffer[4..len]) {
                        Ok(msg) => {
                            read_queue.push_back(msg);
                        }
                        Err(e) => println!("CONTROL in error: {:?}", e)
                    }
                    consumed += len;
                    buffer = &buffer[len..];
                }
            }
            read.consume(consumed);
        }
    }
}
