mod config;
mod keys;
mod store;
mod util;

use config::Config;
use keys::SigningKeys;
use store::CodeStore;

fn main() {
    let config = Config::load();
    let _codes = CodeStore::new();
    let _keys = SigningKeys::generate();
    println!("rust-idp: signing keys ready (issuer={})", config.issuer);
}
