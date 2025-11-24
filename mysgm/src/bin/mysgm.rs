use clap::Parser;
use std::{
    env::home_dir,
    fs::{create_dir_all, read_dir, remove_file},
    thread::sleep,
    time::Duration,
};

/// CLI for secure group messsaging agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Connection string
    connect_string: String,
}

fn main() {
    pretty_env_logger::init();
    // commit cache directory
    let cache_dir = home_dir().unwrap().join(".mysgm/cache");
    create_dir_all(&cache_dir).unwrap();
    // incoming message directory
    let inbox_dir = home_dir().unwrap().join(".mysgm/inbox");
    create_dir_all(&inbox_dir).unwrap();
    // traverse inbox
    for entry in read_dir(&inbox_dir).unwrap() {
        match entry {
            Err(e) => {
                log::error!("Error reading inbox: {e}");
            }
            Ok(entry) => match remove_file(entry.path()) {
                Ok(_) => {
                    log::info!("Removed inbox file {}", entry.path().display());
                }
                Err(e) => {
                    log::error!("Error removing inbox file: {e}");
                }
            },
        }
    }
    // topics
    let commit_key_topic = b"commit-requests";
    let message_topic = b"commits";
    // cli args
    let args = CliArgs::parse();
    log::info!("Command-line arguments: {args:?}");
    // parse connection string
    let connect_string_parts = args.connect_string.split("+").collect::<Vec<&str>>();
    if connect_string_parts.len() != 2 {
        panic!("Invalid connection string format");
    }
    // match on transport provider
    match connect_string_parts[0] {
        "zmq" => {
            let context = zmq::Context::new();
            let publisher = context.socket(zmq::PUB).unwrap();
            publisher.connect(connect_string_parts[1]).unwrap();
            //loop {
            publisher
                .send(commit_key_topic.as_slice(), zmq::SNDMORE)
                .unwrap();
            publisher.send("test", 0).unwrap();
            sleep(Duration::from_millis(1000));
            //}
        }
        _ => {
            log::error!(
                "Unsupported transport provider: {}",
                connect_string_parts[0]
            );
        }
    }
}
