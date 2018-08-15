# Hullrot

**Hullrot** is a minimalist [Mumble](https://mumble.info/) server with
immersive integration with the online role-playing game
[Space Station 13](https://spacestation13.com/).

Features include:

* Local talk by default, so only others in vision range can hear you.
* Push-to-talk over any of the character's available radio channels.
* Handling of intercoms, holopad calls, and hot-miked radios.
* Headsets going inactive if station telecomms is disabled.

Hullrot requires integration with the game server to pass information back and
forth. For an example integration, grep for `hullrot` in
[our tgstation branch](https://github.com/AutomaticFrenzy/tgstation/).

Hullrot is still evolving. If you are interested in using it and the
documentation is insufficient, feel free to contact the author directly.

## Dependencies

The [Rust] compiler:

1. Install the Rust compiler's dependencies (primarily the system linker):

   * Ubuntu: `sudo apt-get install gcc-multilib`
   * Windows (MSVC): [Build Tools for Visual Studio 2017][msvc]
   * Windows (GNU): No action required

1. Use [the Rust installer](https://rustup.rs/), or another Rust installation
   method, or run the following:

    ```sh
    curl https://sh.rustup.rs -sSfo rustup-init.sh
    chmod +x rustup-init.sh
    ./rustup-init.sh
    ```

1. Set the default compiler to **32-bit**:

    ```sh
    # in the `hullrot` directory...
    cd hullrot
    # Linux
    rustup override add stable-i686-unknown-linux-gnu
    # Windows
    rustup override add stable-i686-pc-windows-msvc
    ```

System packages (OpenSSL, Opus, Protobuf):

* Ubuntu and Debian users run:

    ```sh
    sudo apt-get install libssl-dev:i386 libopus-dev:i386 protobuf-compiler pkg-config:i386
    ```

* Windows (GNU/MSYS2) users run:

    ```sh
    pacman -S mingw-w64-i686-{openssl,opus,protobuf}
    ```

* Windows (MSVC) users:
  * Select from [OpenSSL binaries][openssl-bin].
  * Select latest [protoc-win32.zip][protobuf-bin].
  * Rust Opus package will automatically build from bundled sources.

* Other distributions install the appropriate **32-bit development** and
  **32-bit runtime** packages for OpenSSL, Opus, and the Protobuf compiler.

Note: only the BYOND integration *requires* building in 32-bit mode, but the
rest of this README will assume 32-bit for simplicity.

## Compiling

The [cargo] tool handles compilation, as well as automatically downloading and
compiling all Rust dependencies. To compile in release mode (recommended):

```sh
cargo build --release
```

A **binary** (`hullrot.exe` or `hullrot`) and a **library** (`hullrot.dll` or
`libhullrot.so`) will be produced in `target/release`. The binary is the Mumble
server, and the library is a small RPC client for controlling the server
suitable for BYOND integration.

## Hosting

The Hullrot binary is a standalone Mumble server. It expects to be reachable by
players on both TCP and UDP. It also exposes a control channel using a simple
JSON-based RPC. By default, the control channel is only accessible by clients
on the same host.

Running Hullrot for the first time will create a config file `hullrot.toml` as
well as a self-signed certificate. Use `hullrot.toml` to configure the servers,
and use a CA such as [Let's Encrypt](https://letsencrypt.org/) if self-signed
certificates are insufficient.

Passing the name of a config file as a command-line argument will cause Hullrot
to use that config file instead.

### Space Station 13

Hullrot's DM code will need to be integrated into your codebase. The primary
implementation should be straightforward to port to any [/tg/station] fork:

* [controller](https://github.com/AutomaticFrenzy/tgstation/blob/master/code/controllers/subsystem/hullrot.dm)
* [user interface](https://github.com/AutomaticFrenzy/tgstation/blob/master/code/superbox/hullrot.dm)

The exact behavior - who can speak to who when, what radio channels are
available, which mobs are restricted from using the radio - can be understood
by reading and adjusted by modifying the DM code.

The Hullrot library (the `.dll` or `.so` produced earlier) will need to be made
visible to BYOND, either by being placed in the world directory or in BYOND's
`bin` directory. If hosting on Linux, the references to `"hullrot.dll"` in the
DM code will need to be changed to `"libhullrot.so"`.

### Other Games

Games with a similar foreign function interface to BYOND may choose to re-use
the Hullrot library. All functions in the library follow the signature
`extern "C" const char* hullrot_foo(int argc, const char** argv)` and return
responses as a JSON blob. On failure, the blob will be an object with one key,
`"error"`.

* `hullrot_dll_version` - returns the version of the control client library.
  * `{"version": "0.1.0", "major": 0, "minor": 1, "patch": 0}`
  * Clients should check that `major` is exactly the value they expect, and
    that `minor` is at least the value they expect.
  * Ignores its arguments.
* `hullrot_init` - initializes the control connection and returns the first
  control message received from the server.
  * Errors if the control connection could not be made.
    * `{"error": "The connection was refused."}`
  * On success, the first control message should be a `Version`:
    * `{"Version": {"version": "0.1.0", "major": 0, "minor": 1, "patch": 0}}`
  * Clients may check that `major` is exactly the value they expect, and that
    `minor` is at least the value they expect.
  * Ignores its arguments.
* `hullrot_control` - sends each of its arguments (which should be JSON blobs)
  as control messages to the server.
  * Returns a JSON list of control messages received from the server.
  * May be called with no arguments to poll for incoming control messages.
* `hullrot_stop` - disconnect from the server, blocking until completion.
  * Ignores its arguments and returns the empty object `{}`.

Games may also use their own socket facilities. The control channel is a simple
TCP connection. Messages are framed by unsigned big-endian 32-bit integer
length prefixes, and are encoded as JSON blobs.

See the definitions of `enum ControlIn` and `enum ControlOut` in `src/main.rs`
for details on the control messages, and the `integrations/` directory for
example clients.

<!---->

[/tg/station]: https://github.com/tgstation/tgstation
[Rust]: https://rust-lang.org
[cargo]: https://doc.rust-lang.org/cargo/
[rustup]: https://rustup.rs/
[msvc]: https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=15
[openssl-bin]: https://wiki.openssl.org/index.php/Binaries
[protobuf-bin]: https://github.com/google/protobuf/releases

## License

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
