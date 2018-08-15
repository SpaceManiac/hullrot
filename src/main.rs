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

//! Hullrot is a minimalist Mumble server designed for immersive integration
//! with the roleplaying spaceman simulator Space Station 13.
extern crate mio;
extern crate openssl;
extern crate byteorder;
extern crate mumble_protocol;
extern crate opus;
extern crate serde;
extern crate serde_json;
extern crate toml;
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
mod deser;
mod config;

use std::mem::replace;
use std::collections::{VecDeque, HashMap, HashSet};
use std::time::{Instant, Duration};
use std::borrow::Cow;
use std::iter::once;

use mumble_protocol::Permissions;

use config::Config;

pub fn main() {
    if let Err(e) = run() {
        println!("\n{}\n", e);
        std::process::exit(1);
    }
}

pub fn run() -> Result<(), Box<std::error::Error>> {
    let config_path_owned;
    let mut config_path = std::path::Path::new("hullrot.toml");
    let mut config_default = true;

    for arg in std::env::args().skip(1) {
        if arg == "-h" || arg == "--help" || arg == "-V" || arg == "--version" {
            return Ok(usage());
        } else if arg == "--license-mumble" {
            return Ok(mumble_license());
        }
        config_path_owned = std::path::PathBuf::from(arg);
        config_path = &config_path_owned;
        config_default = false;
        break;
    }

    println!("Running in {}", std::env::current_dir().unwrap().display());
    let config = Config::load(config_path, config_default)?;
    net::server_thread(net::init_server(&config)?, &config);
    Ok(())
}

fn usage() {
    println!("{} v{} - {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_DESCRIPTION"));
    println!("Copyright (C) 2017-2018  {}", env!("CARGO_PKG_AUTHORS"));
    println!("
usage: hullrot [<config-file>]
    -h, --help, -V, --version
        show this help
    --license-mumble
        show the license for the Mumble protocol definitions

Hullrot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hullrot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Hullrot.  If not, see <http://www.gnu.org/licenses/>.");
}

fn mumble_license() {
    print!("{}", include_str!("protocol/Mumble.proto.LICENSE"));
}

const WELCOME: &str = "\
    Hullrot is <a href=\"https://github.com/SpaceManiac/hullrot/\">free software</a> \
    available under the GNU Affero General Public License.";

// ----------------------------------------------------------------------------
// Control procotol

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug, Serialize)]
struct Freq(u16);

type Z = i32;
type ZGroup = i32;

const DEADCHAT: Freq = Freq(1);
const GALCOM: &str = "/datum/language/common";

#[derive(Deserialize, Debug, Clone)]
enum ControlIn {
    Debug(String),
    Playing(#[serde(deserialize_with="deser::as_bool")] bool),
    SetMobFlags {
        who: String,
        #[serde(deserialize_with="deser::as_bool")]
        speak: bool,
        #[serde(deserialize_with="deser::as_bool")]
        hear: bool,
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
        #[serde(deserialize_with="deser::as_int")]
        z: Z,
    },
    SetLanguages {
        who: String,
        known: HashSet<String>,
    },
    SetSpokenLanguage {
        who: String,
        spoken: String,
    },
    SetGhost(String),
    SetGhostEars {
        who: String,
        #[serde(deserialize_with="deser::as_bool")]
        ears: bool,
    },
    Linkage(#[serde(deserialize_with="deser::as_map")] HashMap<String, ZGroup>),

    /// Create association between specified cert_hash and ckey.
    Register {
        cert_hash: String,
        ckey: String,
    },
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
        language: String,
    },
    SpeechBubble {
        who: String,
        with: Vec<String>,
    },
    CannotSpeak(String),
    NeedsRegistration {
        untrusted_username: String,
    },
    BadRegistration {
        ckey: String,
    },
}

// ----------------------------------------------------------------------------
// Mumble server

pub struct Server<'cfg> {
    #[allow(dead_code)]
    config: &'cfg Config,
    // used by networking
    read_queue: VecDeque<ControlIn>,
    write_queue: VecDeque<ControlOut>,
    // state
    playing: bool,
    linkage: HashMap<Z, ZGroup>,
    dedup: HashMap<ControlOut, Instant>,
}

impl<'cfg> Server<'cfg> {
    fn new(config: &'cfg Config) -> Server<'cfg> {
        Server {
            config,
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
                let ckey = ckey(&$name);
                let mut once = Some(|$c: &mut Client| $closure);
                _clients.for_each(|c| if c.ckey() == Some(&ckey) {
                    if let Some(cl) = once.take() { cl(c); }
                })
            }}
        }

        while let Some(control_in) = self.read_queue.pop_front() {
            match control_in {
                ControlIn::Debug(msg) => println!("CONTROL dbg: {}", msg),
                ControlIn::Playing(playing) => self.playing = playing,
                ControlIn::Linkage(map) => {
                    self.linkage = map.into_iter().map(|(k, v)| (k.parse().unwrap(), v)).collect();
                },
                ControlIn::SetMobFlags { who, speak, hear } => with_client!(who; |c| {
                    c.mute = !speak;
                    c.deaf = !hear;
                }),
                ControlIn::SetPTT { who, freq } => with_client!(who; |c| c.push_to_talk = freq),
                ControlIn::SetLocalWith { who, with } => with_client!(who; |c| c.local_with = with),
                ControlIn::SetHearFreqs { who, hear } => with_client!(who; |c| c.hear_freqs = hear),
                ControlIn::SetHotFreqs { who, hot } => with_client!(who; |c| c.hot_freqs = hot),
                ControlIn::SetZ { who, z } => with_client!(who; |c| c.z = z),
                ControlIn::SetLanguages { who, known } => with_client!(who; |c| c.known_languages = known),
                ControlIn::SetSpokenLanguage { who, spoken } => with_client!(who; |c| c.current_language = spoken),
                ControlIn::SetGhost(who) => with_client!(who; |c| {
                    c.z = 0;
                    c.mute = false;
                    c.deaf = false;
                    c.current_language = GALCOM.to_owned();
                    c.known_languages = once(GALCOM.to_owned()).collect();
                    c.local_with.clear();
                    c.push_to_talk = None;
                    c.hot_freqs = once(DEADCHAT).collect();
                    c.hear_freqs = once(DEADCHAT).collect();
                }),
                ControlIn::SetGhostEars { who, ears } => with_client!(who; |c| {
                    c.ghost_ears = ears;
                }),
                ControlIn::Register { cert_hash, ckey } => {
                    if let Some(ref auth_db) = self.config.auth_db {
                        let mut applied = false;
                        _clients.for_each(|c| match c.auth_state {
                            AuthState::CertKnown { cert_hash: ref theirs } |
                            AuthState::UsernameKnown { cert_hash: ref theirs, .. } => {
                                if !applied && cert_hash == *theirs {
                                    c.events.push_back(net::Command::AuthCkey(ckey.to_owned()));
                                    applied = true;
                                }
                            }
                            _ => {}
                        });
                        if applied {
                            auth_db.set(&cert_hash, &ckey);
                        } else {
                            self.write_queue.push_back(ControlOut::BadRegistration {
                                ckey: ckey,
                            });
                        }
                    }
                },
            }
        }
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

fn ckey(name: &str) -> String {
    name.chars().filter(|c| c.is_ascii() && c.is_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

#[derive(Debug)]
pub struct Client<'cfg> {
    config: &'cfg Config,
    // used by networking
    sender: net::PacketChannel,
    remote: std::net::SocketAddr,
    disconnected: Option<Cow<'static, str>>,
    events: VecDeque<net::Command>,
    // state
    admin: bool,
    session: u32,
    auth_state: AuthState,

    speaking: bool,  // whether our speech bubble is currently being shown
    self_deaf: bool,  // deafened in the Mumble client

    // language and radio information
    z: Z,  // the Z-level, for subspace comms - 0 is observer
    mute: bool,  // mute (e.g. unconscious, muzzled, no tongue)
    deaf: bool,  // deaf (e.g. unconscious, flashbanged, genetic damage)
    ghost_ears: bool,  // whether all can be heard, only applies when z == 0
    current_language: String,
    known_languages: HashSet<String>,
    local_with: HashSet<String>,  // list of nearby usernames who hear us
    push_to_talk: Option<Freq>,  // current PTT channel, or None for local
    hot_freqs: HashSet<Freq>,  // hot radio channels
    hear_freqs: HashSet<Freq>,  // heard radio channels, e.g. 1459 for common
}

impl<'cfg> Client<'cfg> {
    fn new(config: &'cfg Config, remote: std::net::SocketAddr, sender: net::PacketChannel, session: u32) -> Client {
        sender.send(packet! { Version;
            set_version: 0x10300,
            set_release: concat!("Hullrot v", env!("CARGO_PKG_VERSION")).to_owned(),
            set_os: std::env::consts::FAMILY.into(),
            set_os_version: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        });

        let admin = net::is_loopback(&remote);

        Client {
            config,
            remote,
            session,
            admin,
            sender,
            auth_state: AuthState::Initial,

            disconnected: None,
            events: VecDeque::new(),

            z: 0,
            speaking: false,
            mute: false,
            deaf: false,
            self_deaf: false,
            ghost_ears: false,
            current_language: GALCOM.to_owned(),
            known_languages: once(GALCOM.to_owned()).collect(),
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

    fn quit(&mut self, server: &mut Server, mut others: net::Everyone) {
        self.unspeak(server);
        others.for_each(|other| { other.sender.send(packet! { UserRemove;
            set_session: self.session,
        }); });
    }

    fn unspeak(&mut self, server: &mut Server) {
        if self.speaking {
            self.speaking = false;
            if let Some(ckey) = self.ckey() {
                server.write_queue.push_back(ControlOut::SpeechBubble {
                    who: ckey.to_owned(),
                    with: Vec::new(),
                });
            }
        }
    }

    fn tick(&mut self, server: &mut Server, mut others: net::Everyone) {
        use mumble_protocol::Packet;
        use net::Command;

        while let Some(event) = self.events.pop_front() {
            match event {
                Command::CertHash(hash) => {
                    // only do anything if authentication is enabled
                    let auth_db = if let Some(ref db) = self.config.auth_db {
                        db
                    } else {
                        self.auth_disabled();
                        continue;
                    };

                    // if their client provided no cert, reject them
                    let hash = if let Some(hash) = hash {
                        hash
                    } else {
                        return self.kick("Authentication enabled: your Mumble client must provide a certificate");
                    };

                    if let Some(ckey) = auth_db.get(&hash) {
                        self.auth_ckey(ckey, server, others.reborrow());
                    } else {
                        println!("{} has unrecognized cert hash {:?}", self, hash);
                        self.auth_cert_hash(hash);
                    }
                },
                Command::AuthCkey(ckey) => {
                    self.auth_ckey(ckey, server, others.reborrow());
                },
                Command::Packet(Packet::Authenticate(auth)) => {
                    // Accept the username
                    let name = auth.get_username();
                    if !auth.has_username() || name.is_empty() {
                        return self.kick("No username");
                    }
                    if !auth.get_opus() {
                        return self.kick("No Opus support");
                    }

                    // Log in as a new user or stealthily replace the old one
                    println!("{} provided username {}", self, name);
                    self.auth_username(name.to_owned(), server, others.reborrow());

                    // Bring the client up to speed
                    let permissions = self.permissions();
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
                        set_name: self.config.server_name.to_owned(),
                        set_position: 0,
                        set_max_users: 0,
                    });
                    self.sender.send(packet! { PermissionQuery;
                        set_channel_id: 0,
                        set_permissions: permissions.bits(),
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
                        set_permissions: permissions.bits() as u64,
                    });
                    self.sender.send(packet! { ServerConfig;
                        set_allow_html: false,
                        set_message_length: 2000,
                        set_image_message_length: 131072,
                        set_max_users: 100,
                        set_welcome_text: WELCOME.to_owned(),
                    });
                },
                Command::Packet(Packet::UserState(ref state)) => {
                    if state.has_self_deaf() {
                        self.self_deaf = state.get_self_deaf();
                    }
                },
                Command::Packet(Packet::UserRemove(ref remove)) if self.admin => {
                    let session = remove.get_session();
                    others.for_each(|other| if other.session == session {
                        other.kick(format!("Kicked by {}: {}", self, remove.get_reason()));
                    });
                },
                Command::Packet(_) => {},
                Command::VoiceData { seq, audio, end } => {
                    if !server.playing {
                        // no server connection or pre/post-game
                        others.for_each(|other| {
                            if other.self_deaf { return }
                            other.sender.send_voice(self.session, seq, audio.to_owned());
                        });
                        self.unspeak(server);
                        continue;
                    }

                    let ckey = if let Some(ckey) = self.ckey() { ckey.to_owned() } else { continue };

                    if self.mute {  // bodily mute
                        server.write_with_cooldown(10_000, ControlOut::CannotSpeak(ckey.to_owned()));
                        self.unspeak(server);
                        continue;
                    }

                    // Transmit to anyone who can hear us
                    others.for_each(|other| {
                        if other.self_deaf || other.deaf { return }
                        let other_ckey = if let Some(ckey) = other.ckey() { ckey } else { return };

                        let ptt_heard = match self.push_to_talk {
                            Some(freq) if other.hear_freqs.contains(&freq) => Some(freq),
                            _ => None,
                        };
                        let shared_z = other.ghost() || server.linkage.get(&self.z)
                            .and_then(|&a| server.linkage.get(&other.z).map(|&b| (a, b)))
                            .map_or(self.z == other.z, |(a, b)| a == b);

                        let mut heard = false;
                        if self.local_with.contains(other_ckey) {
                            heard = true;
                            server.write_with_cooldown(10_000, ControlOut::Hear {
                                hearer: other_ckey.to_owned(),
                                speaker: ckey.to_owned(),
                                freq: None,
                                language: self.current_language.to_owned(),
                            });
                        }
                        if shared_z || other.ghost() {
                            for freq in self.hot_freqs.intersection(&other.hear_freqs).cloned().chain(ptt_heard) {
                                heard = true;
                                server.write_with_cooldown(10_000, ControlOut::Hear {
                                    hearer: other_ckey.to_owned(),
                                    speaker: ckey.to_owned(),
                                    freq: Some(freq),
                                    language: self.current_language.to_owned(),
                                });
                            }
                        }
                        if other.ghost() && other.ghost_ears {
                            heard = true;
                        }
                        if heard && (other.known_languages.contains(&self.current_language) || other.ghost()) {
                            other.sender.send_voice(self.session, seq, audio.to_owned());
                        }
                    });

                    // Let us know if we cannot hear ourselves
                    if self.deaf {
                        server.write_with_cooldown(10_000, ControlOut::HearSelf {
                            who: ckey.to_owned(),
                            freq: None,
                            language: self.current_language.to_owned(),
                        });
                    }
                    let ptt_hear_self = match self.push_to_talk {
                        Some(freq) if self.hear_freqs.contains(&freq) => Some(freq),
                        _ => None,
                    };
                    for freq in self.hot_freqs.intersection(&self.hear_freqs).cloned().chain(ptt_hear_self) {
                        server.write_with_cooldown(10_000, ControlOut::HearSelf {
                            who: ckey.to_owned(),
                            freq: Some(freq),
                            language: self.current_language.to_owned(),
                        });
                    }

                    // Show or hide speech bubbles
                    if end {
                        self.unspeak(server);
                    } else if !self.speaking {
                        self.speaking = true;
                        server.write_queue.push_back(ControlOut::SpeechBubble {
                            who: ckey.to_owned(),
                            with: self.local_with.iter().cloned().chain(once(ckey.to_owned())).collect(),
                        });
                    }
                }
            }
        }
    }

    fn permissions(&self) -> Permissions {
        let mut permissions = Permissions::TRAVERSE | Permissions::SPEAK;
        if self.admin {
            permissions |= Permissions::KICK | Permissions::REGISTER | Permissions::REGISTER_SELF | Permissions::ENTER;
        }
        permissions
    }

    fn update_permissions(&self) {
        self.sender.send(packet! { PermissionQuery;
            set_channel_id: 1,
            set_permissions: self.permissions().bits(),
        });
    }

    fn ghost(&self) -> bool {
        self.z == 0
    }
}

impl<'cfg> std::fmt::Display for Client<'cfg> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let AuthState::Active { ref username, .. } = self.auth_state {
            write!(fmt, "{} ({}/{})", username, self.session, self.remote)
        } else {
            write!(fmt, "({}/{})", self.session, self.remote)
        }
    }
}

// ----------------------------------------------------------------------------
// Authentication flow

// The certificate hash is always known before the Mumble Auth is received,
// but the ckey might not be known by that time.

#[derive(Debug)]
enum AuthState {
    // Just connected
    Initial,
    // AuthDB disabled
    AuthDisabled,
    // Cert hash is known, but user has no ckey
    CertKnown {
        cert_hash: String,
    },
    // Cert hash has been matched to ckey
    CkeyKnown {
        ckey: String,
    },
    // Preferred name and hash are known
    UsernameKnown {
        cert_hash: String,
        username: String,
    },
    // Actively chatting
    Active {
        ckey: String,
        username: String,
    },
    Errored,
}

impl<'cfg> Client<'cfg> {
    fn auth_disabled(&mut self) {
        self.auth_state = match replace(&mut self.auth_state, AuthState::Errored) {
            AuthState::Initial => AuthState::AuthDisabled,
            _ => { self.kick("Authentication flow error"); AuthState::Errored }
        };
    }

    fn auth_cert_hash(&mut self, cert_hash: String) {
        self.auth_state = match replace(&mut self.auth_state, AuthState::Errored) {
            AuthState::Initial => AuthState::CertKnown { cert_hash },
            _ => { self.kick("Authentication flow error"); AuthState::Errored }
        };
    }

    fn auth_ckey(&mut self, ckey: String, server: &mut Server, others: net::Everyone) {
        self.auth_state = match replace(&mut self.auth_state, AuthState::Errored) {
            AuthState::Initial => AuthState::CkeyKnown { ckey },
            AuthState::CertKnown { cert_hash: _ } => AuthState::CkeyKnown { ckey },
            AuthState::UsernameKnown { cert_hash: _, username } => self.authenticated(ckey, username, server, others),
            _ => { self.kick("Authentication flow error"); AuthState::Errored }
        };
    }

    fn auth_username(&mut self, username: String, server: &mut Server, others: net::Everyone) {
        // TODO: allow game to override player but not the other way around
        self.auth_state = match replace(&mut self.auth_state, AuthState::Errored) {
            AuthState::UsernameKnown { cert_hash, username: _ } => AuthState::UsernameKnown { cert_hash, username },
            AuthState::CertKnown { cert_hash } => {
                server.write_queue.push_back(ControlOut::NeedsRegistration {
                    untrusted_username: username.to_owned()
                });
                self.sender.send(packet! { TextMessage;
                    set_message: format!("<b>Copy-paste this code in-game to authenticate</b>:<br>{}", cert_hash),
                });
                AuthState::UsernameKnown { cert_hash, username }
            },
            AuthState::CkeyKnown { ckey } => self.authenticated(ckey, username, server, others),
            AuthState::AuthDisabled => self.authenticated(ckey(&username), username, server, others),
            AuthState::Active { ckey, username: _ } => AuthState::Active { ckey, username },
            _ => { self.kick("Authentication flow error"); AuthState::Errored }
        };
    }

    fn authenticated(&mut self, ckey: String, username: String, server: &mut Server, mut others: net::Everyone) -> AuthState {
        println!("{} authenticated as {}", self, ckey);
        server.write_queue.push_back(ControlOut::Refresh(ckey.to_owned()));

        others.for_each(|other| {
            if other.ckey() != Some(&ckey[..]) { return }
            println!("{} inherited from {}", self, other);
            other.kick("Logged in from another client");
            self.session = replace(&mut other.session, 0);

            self.z = other.z;
            self.mute = other.mute;
            self.deaf = other.deaf;
            self.ghost_ears = other.ghost_ears;
            self.current_language = replace(&mut other.current_language, Default::default());
            self.known_languages = replace(&mut other.known_languages, Default::default());
            self.local_with = replace(&mut other.local_with, Default::default());
            self.push_to_talk = replace(&mut other.push_to_talk, Default::default());
            self.hot_freqs = replace(&mut other.hot_freqs, Default::default());
            self.hear_freqs = replace(&mut other.hear_freqs, Default::default());
        });

        others.for_each(|other| {
            if let AuthState::Active { username: ref their_username, .. } = other.auth_state {
                other.sender.send(packet! { UserState;
                    set_session: self.session,
                    set_channel_id: 0,
                    set_name: username.to_owned(),
                    set_hash: "0000000000000000000000000000000000000000".into(),
                });
                self.sender.send(packet! { UserState;
                    set_session: other.session,
                    set_channel_id: 0,
                    set_name: their_username.to_owned(),
                    set_hash: "0000000000000000000000000000000000000000".into(),
                });
            }
        });
        self.update_permissions();

        AuthState::Active { ckey, username }
    }

    fn ckey(&self) -> Option<&str> {
        match self.auth_state {
            AuthState::Active { ref ckey, .. } => Some(ckey),
            _ => None,
        }
    }
}
