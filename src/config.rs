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

use std::collections::BTreeMap;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{self, Read, Write};

use serde::{Deserialize, Deserializer};
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

    /// The path to the server's OpenSSL X509 certificate in PEM format.
    pub cert_pem: String,

    /// The path to the server's OpenSSL X509 private key in PEM format.
    pub key_pem: String,

    /// The path to the database of client certificate hashes.
    ///
    /// Causes the server to ask clients for certificates, match them to ckeys,
    /// and prompt the player to verify with the server if no match was found.
    ///
    /// Currently stored as an unsynchronized TOML file, subject to change.
    #[serde(skip_serializing)]
    pub auth_db: Option<AuthDB>,

    /// Whether the control channel should be debug logged.
    pub verbose_control: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_name: "Hullrot".to_owned(),
            mumble_addr: "0.0.0.0:64738".to_owned(),
            control_addr: "127.0.0.1:10961".to_owned(),
            cert_pem: "cert.pem".to_owned(),
            key_pem: "key.pem".to_owned(),
            auth_db: None,
            verbose_control: false,
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

/// FS-persisted mapping from client certificate hash to verified ckey.
#[derive(Debug)]
pub struct AuthDB {
    path: PathBuf,
    assoc: RefCell<BTreeMap<String, String>>,
}

impl AuthDB {
    fn load_inner(path: &Path) -> Result<BTreeMap<String, String>, Box<::std::error::Error>> {
        let mut buf = Vec::new();
        match File::open(path) {
            Ok(mut file) => { file.read_to_end(&mut buf)?; },
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(Default::default());
            },
            Err(err) => return Err(err.into()),
        }
        toml::de::from_slice(&buf).map_err(From::from)
    }

    /// Load the DB from a file. If it does not exist, silently defaults.
    pub fn load(path: &Path) -> Result<AuthDB, Box<::std::error::Error>> {
        println!("Loading {}", path.display());
        AuthDB::load_inner(path).map(|assoc| AuthDB {
            path: path.to_owned(),
            assoc: RefCell::new(assoc)
        })
    }

    fn save(&self, path: &Path) -> Result<(), Box<::std::error::Error>> {
        File::create(path)?.write_all(&toml::ser::to_vec(&*self.assoc.borrow())?)?;
        Ok(())
    }

    /// Attempt to get an association.
    pub fn get(&self, cert: &str) -> Option<String> {
        self.assoc.borrow().get(cert).cloned()
    }

    /// Set an association. Changes are persisted.
    pub fn set(&self, cert: &str, ckey: &str) {
        self.assoc.borrow_mut().insert(cert.to_owned(), ckey.to_owned());
        if let Err(e) = self.save(&self.path) {
            println!("Error saving {}: {}", self.path.display(), e);
        }
    }
}

impl<'de> Deserialize<'de> for AuthDB {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<AuthDB, D::Error> {
        use serde::de::Error;
        let path = PathBuf::deserialize(de)?;
        AuthDB::load(&path).map_err(D::Error::custom)
    }
}
