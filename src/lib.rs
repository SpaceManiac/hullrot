//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate libc;
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

pub mod ffi;
pub mod net;

use mumble_protocol::Packet;

macro_rules! packet {
    ($ty:path; $($name:ident: $value:expr,)*) => {{
        let mut packet = <$ty>::new();
        $(packet.$name($value);)*
        packet
    }}
}

pub fn hello() {
    net::server_thread();
}

struct Client {
    // used by networking
    sender: net::PacketChannel,
    remote: std::net::SocketAddr,
    disconnected: Option<String>,
    // state
    username: Option<String>,
}

impl Client {
    fn new(remote: std::net::SocketAddr, sender: net::PacketChannel) -> Client {
        use mumble_protocol::*;

        let mut version = Version::new();
        version.set_version(66304);
        version.set_release(concat!("Hullrot v", env!("CARGO_PKG_VERSION")).to_owned());
        sender.send(version);

        Client {
            remote,
            sender,
            disconnected: None,
            username: None,
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(ref name) = self.username {
            write!(fmt, "{} ({})", name, self.remote)
        } else {
            write!(fmt, "({})", self.remote)
        }
    }
}

impl net::Handler for Client {
    type Error = String;

    fn handle(&mut self, packet: Packet) -> Result<(), Self::Error> {
        use mumble_protocol::*;

        // reply to pings
        match packet {
            Packet::Ping(_) => { self.sender.send(packet); return Ok(()) },
            _ => {}
        }
        println!("{:?}", packet);

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
                println!("({}) logged in as {}", self.remote, name);
                self.username = Some(name.to_owned());

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
                    set_permissions: Permissions::DEFAULT.bits(),
                });
                self.sender.send(packet! { UserState;
                    set_session: 1,
                    set_name: name.to_owned(),
                    set_hash: "0000000000000000000000000000000000000000".into(),
                });
                self.sender.send(packet! { ServerSync;
                    set_session: 1,
                    set_max_bandwidth: 72000,
                    set_welcome_text: "Welcome to Hullrot.".into(),
                    set_permissions: Permissions::DEFAULT.bits() as u64,
                });
                self.sender.send(packet! { ServerConfig;
                    set_allow_html: true,
                    set_message_length: 5000,
                    set_image_message_length: 131072,
                    set_max_users: 100,
                });
            }
            _ => {}
        }

        Ok(())
    }

    fn error(&mut self, msg: String) -> std::io::Result<()> {
        self.disconnected = Some(msg);
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}
