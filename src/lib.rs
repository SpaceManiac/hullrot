//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate libc;
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;

pub mod net;

pub fn hello() {
    net::server_thread();
}
