//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate libc;
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;
extern crate opus;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

macro_rules! packet {
    ($ty:ident; $($name:ident: $value:expr,)*) => {{
        let mut packet = ::mumble_protocol::$ty::new();
        $(packet.$name($value);)*
        packet
    }}
}

pub mod ffi;
pub mod net;

use mumble_protocol::Packet;

/// A handle to a running Hullrot server.
pub struct Handle {
    thread: std::thread::JoinHandle<()>,
}

impl Handle {
    /// Attempt to initialize and spawn the server in its child thread.
    pub fn init() -> Result<Handle, String> {
        Ok(Handle {
            thread: std::thread::spawn(net::server_thread),
        })
    }

    /// Block until the server stops or crashes.
    pub fn join(self) {
        let _ = self.thread.join();
    }
}

struct Client {
    // used by networking
    sender: net::PacketChannel,
    remote: std::net::SocketAddr,
    disconnected: Option<String>,
    // state
    admin: bool,
    session: u32,
    username: Option<String>,
}

impl Client {
    fn new(remote: std::net::SocketAddr, sender: net::PacketChannel, session: u32) -> Client {
        sender.send(packet! { Version;
            set_version: 0x10300,
            set_release: concat!("Hullrot v", env!("CARGO_PKG_VERSION")).to_owned(),
            set_os: std::env::consts::FAMILY.into(),
            set_os_version: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        });

        let admin = match remote {
            std::net::SocketAddr::V4(v4) => v4.ip().is_loopback(),
            std::net::SocketAddr::V6(v6) => v6.ip().is_loopback(),
        };

        Client {
            remote,
            sender,
            session,
            admin,
            disconnected: None,
            username: None,
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(ref name) = self.username {
            write!(fmt, "{} ({}/{})", name, self.session, self.remote)
        } else {
            write!(fmt, "({}/{})", self.session, self.remote)
        }
    }
}

impl net::Handler for Client {
    type Error = String;

    fn handle(&mut self, packet: Packet) -> Result<(), Self::Error> {
        use mumble_protocol::*;

        // reply to pings
        match packet {
            Packet::Ping(ping) => {
                self.sender.send(packet! { Ping;
                    set_timestamp: ping.get_timestamp(),
                });
                return Ok(())
            },
            _ => {}
        }
        println!("IN: {:?}", packet);

        // state handling
        match packet {
            Packet::Authenticate(auth) => {
                // Accept the username
                let name = auth.get_username();
                if !auth.has_username() || name.is_empty() {
                    return Err("No username".into());
                }
                if self.username.is_some() {
                    return Err("Double-login".into());
                }
                if !auth.get_opus() {
                    return Err("No Opus support".into());
                }
                println!("{} logged in as {}", self, name);
                self.username = Some(name.to_owned());

                let mut permissions = Permissions::TRAVERSE | Permissions::SPEAK;
                if self.admin {
                    permissions |= Permissions::KICK | Permissions::REGISTER | Permissions::REGISTER_SELF | Permissions::ENTER;
                }

                self.sender.send(packet! { CryptSetup;
                    set_key: vec![0; 16],
                    set_client_nonce: vec![0; 16],
                    set_server_nonce: vec![0; 16],
                });
                self.sender.send(packet! { CodecVersion;
                    set_alpha: -2147483637,
                    set_beta: 0,
                    set_prefer_alpha: true,
                    set_opus: true,
                });
                self.sender.send(packet! { ChannelState;
                    set_channel_id: 0,
                    set_name: "Hullrot".into(),
                    set_position: 0,
                    set_max_users: 0,
                });
                self.sender.send(packet! { PermissionQuery;
                    set_channel_id: 0,
                    set_permissions: permissions.bits(),
                });
                self.sender.send(packet! { UserState;
                    set_session: 1,
                    set_channel_id: 0,
                    set_name: "System".to_owned(),
                    set_hash: "0000000000000000000000000000000000000000".into(),
                });
                self.sender.send(packet! { UserState;
                    set_session: self.session,
                    set_channel_id: 0,
                    set_name: name.to_owned(),
                    set_hash: "0000000000000000000000000000000000000000".into(),
                });
                self.sender.send(packet! { ServerSync;
                    set_session: self.session,
                    set_max_bandwidth: 72000,
                    set_welcome_text: "Welcome to Hullrot.".into(),
                    set_permissions: permissions.bits() as u64,
                });
                self.sender.send(packet! { ServerConfig;
                    set_allow_html: false,
                    set_message_length: 2000,
                    set_image_message_length: 131072,
                    set_max_users: 100,
                });
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_voice(&mut self, seq: i64, voice: &[net::Sample]) -> Result<(), Self::Error> {
        self.sender.send_voice(1, seq, voice.to_owned());
        Ok(())
    }

    fn error(&mut self, msg: String) -> std::io::Result<()> {
        self.disconnected = Some(msg);
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}
