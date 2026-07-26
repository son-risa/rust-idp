mod config;
mod store;
mod util;

use config::Config;
use store::CodeStore;

fn main() {
    let config = Config::load();
    let _codes = CodeStore::new();
    println!("rust-idp: domain scaffolding ready (issuer={})", config.issuer);
}
