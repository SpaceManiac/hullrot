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
use std::io::{self, Read, Write};

use toml;

/// Configuration details for the Hullrot server.
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    /// The name of the server's root channel.
    pub server_name: String,

    /// The socket address which the Mumble server will host on.
    /// Defaults to all interfaces on the default Mumble port 64738.
    pub mumble_addr: String,

    /// The socket address which the control interface will host on.
    /// Defaults to localhost only on the default Hullrot port 10961.
    pub control_addr: String,

    /// The path at which the OpenSSL `cert.pem` file may be found.
    pub cert_pem: String,

    /// The path at which the OpenSSL `key.pem` file may be found.
    pub key_pem: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_name: "Hullrot".to_owned(),
            mumble_addr: "0.0.0.0:64738".to_owned(),
            control_addr: "127.0.0.1:10961".to_owned(),
            cert_pem: "cert.pem".to_owned(),
            key_pem: "key.pem".to_owned(),
        }
    }
}

impl Config {
    /// Load the config from a file.
    pub fn load(path: &Path, default: bool) -> Result<Config, Box<::std::error::Error>> {
        println!("Loading {}", path.display());
        let mut buf = Vec::new();
        match File::open(path) {
            Ok(mut file) => { file.read_to_end(&mut buf)?; },
            Err(ref err) if default && err.kind() == io::ErrorKind::NotFound => {
                println!("Not found, using defaults");
                let cfg = Config::default();
                let _ = cfg.save(path);
                return Ok(cfg);
            },
            Err(err) => return Err(err.into()),
        }
        let root: DeRoot = toml::de::from_slice(&buf)?;
        Ok(root.hullrot)
    }

    /// Save the config to a file.
    fn save(&self, path: &Path) -> Result<(), Box<::std::error::Error>> {
        let mut file = File::create(path)?;
        file.write_all(&toml::ser::to_vec(&SerRoot { hullrot: self })?)?;
        Ok(())
    }
}

// Wrappers used to put the whole config inside `[hullrot]`.
#[derive(Deserialize)]
struct DeRoot {
    hullrot: Config,
}

#[derive(Serialize)]
struct SerRoot<'a> {
    hullrot: &'a Config,
}
