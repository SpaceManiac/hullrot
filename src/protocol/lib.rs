pub extern crate protobuf;
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
pub use generated::*;
