pub extern crate protobuf;
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
