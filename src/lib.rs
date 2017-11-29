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
    type Error = ();

    fn handle(&mut self, packet: Packet) -> Result<(), Self::Error> {
        // reply to pings
        match packet {
            Packet::Ping(_) => return Ok(self.sender.send(packet).unwrap()),
            _ => {}
        }
        println!("{:?}", packet);

        Ok(())
    }

    fn error(&mut self, _: ()) -> std::io::Result<()> {
        self.disconnected = Some("Terminated".into());
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}
