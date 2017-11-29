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

                // TODO: UDP crypto setup

                // Channel states
                let mut channel_state = ChannelState::new();
                channel_state.set_name("Hullrot".into());
                channel_state.set_description("Description here".into());
                self.sender.send(channel_state);

                // TODO: user states

                // Indicate we are done with the channel info
                /*let mut server_sync = ServerSync::new();
                server_sync.set_session(1);
                server_sync.set_max_bandwidth(72000);
                server_sync.set_welcome_text("Welcome to Hullrot.".into());
                self.sender.send(server_sync);*/

                let mut text_message = TextMessage::new();
                text_message.set_message("Borpo".into());
                self.sender.send(text_message);
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
