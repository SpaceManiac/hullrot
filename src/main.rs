//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;
extern crate opus;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;

extern crate hullrot;

macro_rules! packet {
    ($ty:ident; $($name:ident: $value:expr,)*) => {{
        let mut packet = ::mumble_protocol::$ty::new();
        $(packet.$name($value);)*
        packet
    }}
}

pub mod net;

use std::collections::{VecDeque, HashMap, HashSet};
use std::time::{Instant, Duration};
use std::borrow::Cow;

pub fn main() {
    net::server_thread(net::init_server().unwrap());
}

// ----------------------------------------------------------------------------
// Control procotol

type Freq = u16;
type Z = i32;

#[derive(Deserialize, Debug, Clone)]
enum ControlIn {
    Debug(String),
    Playing(i32),
    SetMobFlags {
        who: String,
        speak: i32,
        hear: i32,
    },
    SetPTT {
        who: String,
        freq: Option<Freq>,
    },
    SetLocalWith {
        who: String,
        with: HashSet<String>,
    },
    SetHearFreqs {
        who: String,
        hear: HashSet<Freq>,
    },
    SetHotFreqs {
        who: String,
        hot: HashSet<Freq>,
    },
    SetZ {
        who: String,
        z: Z,
    },
    SetGhost(String),
    Linkage(HashMap<String, i32>),
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, Hash)]
enum ControlOut {
    Version {
        version: &'static str,
        major: u32,
        minor: u32,
        patch: u32,
    },
    Refresh(String),
    Hear {
        hearer: String,
        speaker: String,
        freq: Option<Freq>,
        language: String,
    },
    HearSelf {
        who: String,
        freq: Option<Freq>,
    },
}

// ----------------------------------------------------------------------------
// Mumble server

pub struct Server {
    // used by networking
    read_queue: VecDeque<ControlIn>,
    write_queue: VecDeque<ControlOut>,
    // state
    playing: bool,
    linkage: HashMap<Z, i32>,
    dedup: HashMap<ControlOut, Instant>,
}

impl Server {
    fn new() -> Server {
        Server {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            playing: false,
            linkage: HashMap::new(),
            dedup: HashMap::new(),
        }
    }

    fn connect(&mut self) {
        self.write_queue.clear();
        self.write_queue.push_back(ControlOut::Version {
            version: env!("CARGO_PKG_VERSION"),
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap(),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().unwrap(),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().unwrap(),
        });
    }

    fn disconnect(&mut self) {
        self.playing = false;
    }

    fn tick(&mut self, mut _clients: net::Everyone) {
        macro_rules! with_client {
            ($name:expr; |$c:ident| $closure:expr) => {{
                let mut once = Some(|$c: &mut Client| $closure);
                _clients.for_each(|c| if c.ckey == $name {
                    if let Some(cl) = once.take() { cl(c); }
                })
            }}
        }

        while let Some(control_in) = self.read_queue.pop_front() {
            match control_in {
                ControlIn::Debug(msg) => println!("CONTROL dbg: {}", msg),
                ControlIn::Playing(playing) => self.playing = playing != 0,
                ControlIn::Linkage(map) => {
                    self.linkage = map.into_iter().map(|(k, v)| (k.parse().unwrap(), v)).collect();
                },
                ControlIn::SetMobFlags { who, speak, hear } => with_client!(who; |c| {
                    c.mute = speak == 0;
                    c.deaf = hear == 0;
                }),
                ControlIn::SetPTT { who, freq } => with_client!(who; |c| c.push_to_talk = freq),
                ControlIn::SetLocalWith { who, with } => with_client!(who; |c| c.local_with = with),
                ControlIn::SetHearFreqs { who, hear } => with_client!(who; |c| c.hear_freqs = hear),
                ControlIn::SetHotFreqs { who, hot } => with_client!(who; |c| c.hot_freqs = hot),
                ControlIn::SetZ { who, z } => with_client!(who; |c| c.z = z),
                ControlIn::SetGhost(who) => with_client!(who; |c| c.z = 0),
            }
        }

        // ...
    }

    fn write_with_cooldown(&mut self, ms: u64, message: ControlOut) {
        let now = Instant::now();
        self.dedup.retain(|_, v| *v >= now);
        if !self.dedup.contains_key(&message) {
            self.dedup.insert(message.clone(), now + Duration::from_millis(ms));
            self.write_queue.push_back(message);
        }
    }
}

#[derive(Debug)]
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
    z: Z,  // the Z-level, for subspace comms
    ckey: String,
    mute: bool,  // mute (e.g. unconscious, muzzled, no tongue)
    deaf: bool,  // deaf (e.g. unconscious, flashbanged, genetic damage)
    current_language: String,
    known_languages: HashSet<String>,
    local_with: HashSet<String>,  // list of nearby usernames who hear us
    push_to_talk: Option<Freq>,  // current PTT channel, or None for local
    hot_freqs: HashSet<Freq>,  // hot radio channels
    hear_freqs: HashSet<Freq>,  // heard radio channels, e.g. 1459 for common
}

impl Client {
    fn new(remote: std::net::SocketAddr, sender: net::PacketChannel, session: u32) -> Client {
        sender.send(packet! { Version;
            set_version: 0x10300,
            set_release: concat!("Hullrot v", env!("CARGO_PKG_VERSION")).to_owned(),
            set_os: std::env::consts::FAMILY.into(),
            set_os_version: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        });

        let admin = net::is_loopback(&remote);

        Client {
            remote,
            session,
            admin,
            sender,

            disconnected: None,
            username: None,
            events: VecDeque::new(),

            z: 0,
            ckey: String::new(),
            deaf: false,
            mute: false,
            current_language: "common".to_owned(),
            known_languages: Some("common".to_owned()).into_iter().collect(),
            local_with: HashSet::new(),
            push_to_talk: None,
            hot_freqs: HashSet::new(),
            hear_freqs: HashSet::new(),
        }
    }

    fn kick<T: Into<Cow<'static, str>>>(&mut self, message: T) {
        if self.disconnected.is_none() {
            self.disconnected = Some(message.into());
        }
    }

    fn quit(&mut self, _server: &mut Server, mut others: net::Everyone) {
        others.for_each(|other| { other.sender.send(packet! { UserRemove;
            set_session: self.session,
        }); });
    }

    fn tick(&mut self, server: &mut Server, mut others: net::Everyone) {
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
                    self.ckey = ckey(name);
                    server.write_queue.push_back(ControlOut::Refresh(self.ckey.to_owned()));

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
                    /*self.sender.send(packet! { UserState;
                        set_session: 1,
                        set_channel_id: 0,
                        set_name: "System".to_owned(),
                        set_hash: "0000000000000000000000000000000000000000".into(),
                    });*/
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
                        set_permissions: permissions.bits() as u64,
                    });
                    self.sender.send(packet! { ServerConfig;
                        set_allow_html: false,
                        set_message_length: 2000,
                        set_image_message_length: 131072,
                        set_max_users: 100,
                    });
                },
                Command::Packet(Packet::UserRemove(ref remove)) if self.admin => {
                    let session = remove.get_session();
                    others.for_each(|other| if other.session == session {
                        other.kick(format!("Kicked by {}: {}", self, remove.get_reason()));
                    });
                },
                Command::Packet(_) => {},
                Command::VoiceData { who: _, seq, audio } => {
                    if !server.playing {
                        // no server connection or pre/post-game
                        others.for_each(|other| {
                            other.sender.send_voice(self.session, seq, audio.to_owned());
                        });
                        continue
                    } else if self.mute {
                        continue  // bodily mute
                    } else if self.ckey.is_empty() {
                        continue
                    }

                    // Transmit to anyone who can hear us
                    others.for_each(|other| {
                        if other.deaf || other.ckey.is_empty() { return }

                        let lang = &self.current_language;
                        let lang_known = other.known_languages.contains(lang);
                        let ptt_heard = match self.push_to_talk {
                            Some(freq) if other.hear_freqs.contains(&freq) => Some(freq),
                            _ => None,
                        };
                        let shared_z = server.linkage.get(&self.z)
                            .and_then(|&a| server.linkage.get(&other.z).map(|&b| (a, b)))
                            .map_or(self.z == other.z, |(a, b)| a == b);

                        let mut heard = false;
                        if self.local_with.contains(&other.ckey) {
                            heard = true;
                            server.write_with_cooldown(10_000, ControlOut::Hear {
                                hearer: other.ckey.to_owned(),
                                speaker: self.ckey.to_owned(),
                                freq: None,
                                language: self.current_language.to_owned(),
                            });
                        }
                        if shared_z {
                            for freq in self.hot_freqs.intersection(&other.hear_freqs).cloned().chain(ptt_heard) {
                                heard = true;
                                server.write_with_cooldown(10_000, ControlOut::Hear {
                                    hearer: other.ckey.to_owned(),
                                    speaker: self.ckey.to_owned(),
                                    freq: Some(freq),
                                    language: self.current_language.to_owned(),
                                });
                            }
                        }
                        if heard && lang_known {
                            other.sender.send_voice(self.session, seq, audio.to_owned());
                        }
                    });

                    // Let us know if we can hear ourselves
                    server.write_with_cooldown(10_000, ControlOut::HearSelf {
                        who: self.ckey.to_owned(),
                        freq: None,
                    });
                    let ptt_hear_self = match self.push_to_talk {
                        Some(freq) if self.hear_freqs.contains(&freq) => Some(freq),
                        _ => None,
                    };
                    for freq in self.hot_freqs.intersection(&self.hear_freqs).cloned().chain(ptt_hear_self) {
                        server.write_with_cooldown(10_000, ControlOut::HearSelf {
                            who: self.ckey.to_owned(),
                            freq: Some(freq),
                        });
                    }
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

fn ckey(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii() && c.is_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}
