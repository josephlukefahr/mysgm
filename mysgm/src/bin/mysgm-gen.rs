use clap::Parser;
use std::{env::home_dir, fs::create_dir_all};

fn main() {
    pretty_env_logger::init();
    // mysgm root directory
    let root_dir = home_dir().unwrap().join(".mysgm");
    create_dir_all(&root_dir).unwrap();
}
