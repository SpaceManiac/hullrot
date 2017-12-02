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
mod net;

use std::collections::{VecDeque, HashSet};
use std::borrow::Cow;

/// A handle to a running Hullrot server.
pub struct Handle {
    thread: std::thread::JoinHandle<()>,
}

impl Handle {
    /// Attempt to initialize and spawn the server in its child thread.
    pub fn init() -> Result<Handle, String> {
        match net::init_server() {
            Ok(init) => Ok(Handle {
                thread: std::thread::spawn(|| net::server_thread(init)),
            }),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Block until the server stops or crashes.
    pub fn join(self) {
        let _ = self.thread.join();
    }
}

pub struct Client {
    // used by networking
    sender: net::PacketChannel,
    remote: std::net::SocketAddr,
    disconnected: Option<Cow<'static, str>>,
    events: VecDeque<net::Command>,
    // state
    admin: bool,
    session: u32,
    username: Option<String>,
    // language and radio information
    mute: bool,  // mute (e.g. muzzled or biologically mute)
    deaf: bool,  // deaf (e.g. flashbanged or biologically deaf)
    current_language: String,
    known_languages: HashSet<String>,
    local_with: HashSet<String>,  // list of nearby usernames we can hear
    push_to_talk: Option<u16>,  // current PTT channel, or None for local
    speaking_radio: HashSet<u16>,  // hot radio channels
    listening_radio: HashSet<u16>,  // heard radio channels, e.g. 1459 for common
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
            session,
            admin,
            sender,

            disconnected: None,
            username: None,
            events: VecDeque::new(),

            deaf: false,
            mute: false,
            current_language: "common".to_owned(),
            known_languages: Some("common".to_owned()).into_iter().collect(),
            local_with: HashSet::new(),
            push_to_talk: Some(1459),
            speaking_radio: HashSet::new(),
            listening_radio: Some(1459).into_iter().collect(),
        }
    }

    fn kick<T: Into<Cow<'static, str>>>(&mut self, message: T) {
        if self.disconnected.is_none() {
            self.disconnected = Some(message.into());
        }
    }

    fn quit(&mut self, mut others: net::EveryoneElse) {
        others.for_each(|other| { other.sender.send(packet! { UserRemove;
            set_session: self.session,
        }); });
    }

    fn tick(&mut self, mut others: net::EveryoneElse) {
        use mumble_protocol::{Packet, Permissions};
        use net::Command;

        while let Some(event) = self.events.pop_front() {
            match event {
                Command::Packet(Packet::Authenticate(auth)) => {
                    // Accept the username
                    let name = auth.get_username();
                    if !auth.has_username() || name.is_empty() {
                        return self.kick("No username");
                    }
                    if self.username.is_some() {
                        return self.kick("Double-login");
                    }
                    if !auth.get_opus() {
                        return self.kick("No Opus support");
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
                    others.for_each(|other| {
                        if let Some(ref username) = other.username {
                            other.sender.send(packet! { UserState;
                                set_session: self.session,
                                set_channel_id: 0,
                                set_name: if other.admin { name.to_owned() } else { "???".to_owned() },
                                set_hash: "0000000000000000000000000000000000000000".into(),
                            });
                            self.sender.send(packet! { UserState;
                                set_session: other.session,
                                set_channel_id: 0,
                                set_name: if self.admin { username.to_owned() } else { "???".to_owned() },
                                set_hash: "0000000000000000000000000000000000000000".into(),
                            });
                        }
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
                },
                Command::Packet(_) => {},
                Command::VoiceData { who: _, seq, audio } => {
                    if self.mute { return }
                    let username = match self.username {
                        Some(ref username) => username,
                        None => continue,
                    };

                    others.for_each(|other| {
                        if other.deaf { return }
                        let lang = &self.current_language;
                        let lang_known = other.known_languages.contains(lang);
                        let local_heard = other.local_with.contains(username);
                        let ptt_heard = self.push_to_talk.map_or(false, |freq| other.listening_radio.contains(&freq));
                        let hot_heard = self.speaking_radio.intersection(&other.listening_radio).next().is_some();

                        //println!("{} -> {} -- {}={} {}/{}/{}", self, other, lang, lang_known, local_heard, ptt_heard, hot_heard);
                        if lang_known && (local_heard || ptt_heard || hot_heard) {
                            other.sender.send_voice(self.session, seq, audio.to_owned());
                        }
                    })
                }
            }
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
