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

extern crate protoc_rust;

use std::io::Write;

fn main() {
    // run protoc
    let out_dir = std::env::var("OUT_DIR").expect("missing OUT_DIR");
    if let Err(e) = protoc_rust::Codegen::new()
        .input("Mumble.proto")
        .out_dir(&out_dir)
        .run()
    {
        eprintln!("Failed to run the protobuf code generator.");
        eprintln!("Ensure that `protoc` is available and on the PATH.");
        eprintln!();
        eprintln!("{}", e);
        eprintln!("{:?}", e);
        std::process::exit(1);
    }

    // workaround for https://github.com/rust-lang/rust/issues/18810
    std::fs::File::create(format!("{}/generated.rs", out_dir))
        .unwrap()
        .write_all(format!("#[path = {:?}] mod generated;", format!("{}/Mumble.rs", out_dir)).as_bytes())
        .unwrap();
}
