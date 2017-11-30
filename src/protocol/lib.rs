pub extern crate protobuf;
extern crate byteorder;
#[macro_use] extern crate bitflags;

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub use generated::*;

macro_rules! packets {
    ($($num:expr => $name:ident;)*) => {
        #[derive(Debug, Clone, PartialEq)]
        pub enum Packet {
            $($name($name),)*
        }

        impl Packet {
            pub fn parse(ty: u16, buf: &[u8]) -> protobuf::ProtobufResult<Packet> {
                match ty {
                    $($num => protobuf::parse_from_bytes::<$name>(buf).map(Packet::$name),)*
                    _ => Err(protobuf::ProtobufError::message_not_initialized("unknown opcode"))
                }
            }

            pub fn encode(&self) -> protobuf::ProtobufResult<Vec<u8>> {
                use byteorder::{BigEndian, WriteBytesExt};
                use protobuf::Message;

                let mut result = Vec::new();
                match *self {
                    $(Packet::$name(ref inner) => {
                        result.write_u16::<BigEndian>($num)?;
                        result.write_u32::<BigEndian>(inner.compute_size())?;
                        inner.write_to_vec(&mut result)?;
                    })*
                }
                Ok(result)
            }
        }

        $(impl From<$name> for Packet {
            fn from(inner: $name) -> Packet {
                Packet::$name(inner)
            }
        })*
    }
}

packets! {
    0 => Version;
    1 => UDPTunnel;
    2 => Authenticate;
    3 => Ping;
    4 => Reject;
    5 => ServerSync;
    6 => ChannelRemove;
    7 => ChannelState;
    8 => UserRemove;
    9 => UserState;
    10 => BanList;
    11 => TextMessage;
    12 => PermissionDenied;
    13 => ACL;
    14 => QueryUsers;
    15 => CryptSetup;
    16 => ContextActionModify;
    17 => ContextAction;
    18 => UserList;
    19 => VoiceTarget;
    20 => PermissionQuery;
    21 => CodecVersion;
    22 => UserStats;
    23 => RequestBlob;
    24 => ServerConfig;
    25 => SuggestConfig;
}

bitflags! {
    pub struct Permissions: u32 {
        /// Write access to channel control. Implies all other permissions
        /// (except Speak).
        const WRITE = 0x01;
        /// Traverse channel. Without this, a client cannot reach subchannels,
        /// no matter which privileges he has there.
        const TRAVERSE = 0x02;
        /// Enter channel.
        const ENTER = 0x04;
        /// Speak in channel.
        const SPEAK = 0x08;
        /// Whisper to channel. This is different from Speak, so you can set up
        /// different permissions.
        const WHISPER = 0x100;
        /// Mute and deafen other users in this channel.
        const MUTE_DEAFEN = 0x10;
        /// Move users from channel. You need this permission in both the
        /// source and destination channel to move another user.
        const MOVE = 0x20;
        /// Make new channel as a subchannel of this channel.
        const MAKE_CHANNEL = 0x40;
        /// Make new temporary channel as a subchannel of this channel.
        const MAKE_TEMP_CHANNEL = 0x400;
        /// Link this channel. You need this permission in both the source and
        /// destination channel to link channels, or in either channel to
        /// unlink them.
        const LINK_CHANNEL = 0x80;
        /// Send text message to channel.
        const TEXT_MESSAGE = 0x200;

        /// Kick user from server. Only valid on root channel.
        const KICK = 0x10000;
        /// Ban user from server. Only valid on root channel.
        const BAN = 0x20000;
        /// Register and unregister users. Only valid on root channel.
        const REGISTER = 0x40000;
        /// Register and unregister users. Only valid on root channel.
        const REGISTER_SELF = 0x80000;

        const DEFAULT = Self::TRAVERSE.bits | Self::ENTER.bits |
            Self::SPEAK.bits | Self::WHISPER.bits | Self::TEXT_MESSAGE.bits |
            Self::REGISTER_SELF.bits;
    }
}
