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

//! Configuration handling.

use std::path::Path;
use std::fs::File;
use std::io::{self, Read};

use toml;

/// Configuration details for the Hullrot server.
#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    /// The path at which the OpenSSL `cert.pem` file may be found.
    pub cert_pem: String,

    /// The path at which the OpenSSL `key.pem` file may be found.
    pub key_pem: String,

    /// The socket address which the Mumble server will host on.
    /// Defaults to all interfaces on the default Mumble port 64738.
    pub mumble_addr: String,

    /// The socket address which the control interface will host on.
    /// Defaults to localhost only on the default Hullrot port 10961.
    pub control_addr: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            cert_pem: "cert.pem".to_owned(),
            key_pem: "key.perm".to_owned(),
            mumble_addr: "0.0.0.0:64738".to_owned(),
            control_addr: "127.0.0.1:10961".to_owned(),
        }
    }
}

/// Wrapper used to put the whole config inside `[hullrot]`.
#[derive(Deserialize)]
struct ConfigRoot {
    hullrot: Config,
}

/// Load the config from a file.
pub fn load_config(path: &Path) -> Result<Config, Box<::std::error::Error>> {
    println!("Loading {}", path.display());
    let mut buf = Vec::new();
    match File::open(path) {
        Ok(mut file) => { file.read_to_end(&mut buf)?; },
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
            println!("Not found, using defaults");
            return Ok(Config::default())
        },
        Err(err) => return Err(err.into()),
    }
    let root: ConfigRoot = toml::de::from_slice(&buf)?;
    Ok(root.hullrot)
}
