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

OpenSSL:

* Ubuntu and Debian users run:

    ```sh
    sudo apt-get install libssl-dev:i386 pkg-config:i386
    ```

* Windows (GNU/MSYS2) users run:

    ```sh
    pacman -S mingw64-mingw-w64-i686-openssl
    ```

* Windows (MSVC) users select from [available binaries][openssl-bin].

* Other distributions install the appropriate **32-bit development** and
  **32-bit runtime** packages.

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
the Hullrot library. Otherwise they may use their own socket facilities.

The control channel is a simple TCP socket.
Messages are framed by unsigned big-endian 32-bit integer length prefixes, and
are encoded as JSON blobs.

See the definition of `enum ControlIn` and `enum ControlOut` in `src/main.rs`
for details on the messages supported, and the `integrations/` directory for
examples.

<!---->

[/tg/station]: https://github.com/tgstation/tgstation
[Rust]: https://rust-lang.org
[cargo]: https://doc.rust-lang.org/cargo/
[rustup]: https://rustup.rs/
[msvc]: https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=15
[openssl-bin]: https://wiki.openssl.org/index.php/Binaries

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
