//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate libc;
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;

pub mod net;

use mumble_protocol::Packet;

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

        const PERMISSIONS: u32 = 134742798;

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

                let mut crypt_setup = CryptSetup::new();
                crypt_setup.set_key(vec![0; 16]);
                crypt_setup.set_client_nonce(vec![0; 16]);
                crypt_setup.set_server_nonce(vec![0; 16]);
                self.sender.send(crypt_setup);

                let mut codec_version = CodecVersion::new();
                codec_version.set_alpha(-2147483637);
                codec_version.set_beta(0);
                codec_version.set_prefer_alpha(true);
                codec_version.set_opus(false);
                self.sender.send(codec_version);

                let mut channel_state = ChannelState::new();
                channel_state.set_channel_id(0);
                channel_state.set_name("Root".into());
                channel_state.set_position(0);
                //channel_state.set_description("Description here".into());
                channel_state.set_max_users(0);
                self.sender.send(channel_state);

                let mut permission_query = PermissionQuery::new();
                permission_query.set_channel_id(0);
                permission_query.set_permissions(PERMISSIONS);
                self.sender.send(permission_query);

                let mut user_state = UserState::new();
                user_state.set_session(1);  // TODO
                user_state.set_name(name.to_owned());
                user_state.set_hash("0000000000000000000000000000000000000000".into());
                self.sender.send(user_state);

                let mut server_sync = ServerSync::new();
                server_sync.set_session(1);
                server_sync.set_max_bandwidth(72000);
                server_sync.set_welcome_text("Welcome to Hullrot.".into());
                server_sync.set_permissions(PERMISSIONS as u64);
                self.sender.send(server_sync);

                let mut server_config = ServerConfig::new();
                server_config.set_allow_html(true);
                server_config.set_message_length(5000);
                server_config.set_image_message_length(131072);
                server_config.set_max_users(100);
                self.sender.send(server_config);
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
