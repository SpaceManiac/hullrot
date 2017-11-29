pub extern crate protobuf;
extern crate byteorder;

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
