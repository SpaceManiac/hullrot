extern crate protoc_rust;

use std::io::Write;

fn main() {
    // run protoc
    let out_dir = std::env::var("OUT_DIR").expect("missing OUT_DIR");
    if let Err(e) = protoc_rust::run(protoc_rust::Args {
        input: &["Mumble.proto"],
        out_dir: &out_dir,
        includes: &[],
    }) {
        println!("Failed to run the protobuf code generator.");
        println!("Ensure that `protoc` is available and on the PATH.");
        println!();
        println!("{}", e);
        println!("{:?}", e);
    }

    // workaround for https://github.com/rust-lang/rust/issues/18810
    std::fs::File::create(&format!("{}/generated.rs", out_dir))
        .unwrap()
        .write_all(format!("#[path = {:?}] mod generated;", format!("{}/Mumble.rs", out_dir)).as_bytes())
        .unwrap();
}
