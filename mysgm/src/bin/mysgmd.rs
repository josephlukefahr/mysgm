use clap::Parser;
use std::{
    env::home_dir,
    fs::{File, create_dir_all},
    io::{BufReader, Read, Write},
    path::Path,
    str::from_utf8 as str_from_utf8,
};
use uuid::Uuid;

/// CLI for secure group messsaging agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Connection string
    connect_string: String,
}

fn query_cache(key: &[u8], cache_dir: &Path) -> Option<Vec<u8>> {
    match str_from_utf8(key) {
        Err(e) => {
            log::error!("Invalid UTF-8 in cache key: {e}");
            None
        }
        Ok(key) => match File::open(cache_dir.join(key)) {
            Err(e) => {
                log::error!("Cache miss for {key}: {e}");
                None
            }
            Ok(file) => {
                let mut data = Vec::new();
                match BufReader::new(file).read_to_end(&mut data) {
                    Err(e) => {
                        log::error!("Error reading cached data for key {key}: {e}");
                        None
                    }
                    Ok(_) => {
                        log::info!("Cache hit for {key}");
                        Some(data)
                    }
                }
            }
        },
    }
}

fn handle_message(data: &[u8], inbox_dir: &Path) {
    // validate incoming message
    // save to unique file
    let uuid_str = String::from(Uuid::now_v7());
    match File::create_new(inbox_dir.join(&uuid_str)).and_then(|mut file| file.write_all(data)) {
        Err(e) => {
            log::error!("Error saving incoming message to file: {e}");
        }
        Ok(_) => {
            log::info!("Incoming message {uuid_str}");
        }
    }
}

fn main() {
    pretty_env_logger::init();
    // commit cache directory
    let cache_dir = home_dir().unwrap().join(".mysgm/cache");
    create_dir_all(&cache_dir).unwrap();
    // incoming message directory
    let inbox_dir = home_dir().unwrap().join(".mysgm/inbox");
    create_dir_all(&inbox_dir).unwrap();
    // topics
    let commit_key_topic = b"commit-requests";
    let message_topic = b"commits";
    // cli args
    let args = CliArgs::parse();
    log::info!("{args:?}");
    // parse connection string
    let connect_string_parts = args.connect_string.split("+").collect::<Vec<&str>>();
    if connect_string_parts.len() != 2 {
        panic!("Invalid connection string format");
    }
    // match on transport provider
    match connect_string_parts[0] {
        "zmq" => {
            // zmq pub/sub connection
            let context = zmq::Context::new();
            let publisher = context.socket(zmq::PUB).unwrap();
            publisher.connect(connect_string_parts[1]).unwrap();
            let subscriber = context.socket(zmq::SUB).unwrap();
            subscriber.connect(connect_string_parts[1]).unwrap();
            subscriber.set_subscribe(commit_key_topic).unwrap();
            subscriber.set_subscribe(message_topic).unwrap();
            log::info!("ZMQ subscriber {}", connect_string_parts[1]);
            // main loop for zmq
            loop {
                // listen for message
                match subscriber
                    .recv_msg(0)
                    .and_then(|topic| subscriber.recv_msg(0).and_then(|data| Ok((topic, data))))
                {
                    Err(e) => {
                        // log error and loop
                        log::error!("Error receiving message: {e}");
                    }
                    Ok((topic, data)) => match topic.as_ref() {
                        t if t == commit_key_topic => {
                            if let Some(data) = query_cache(data.as_ref(), &cache_dir) {
                                if let Err(e) = publisher
                                    .send(message_topic.as_slice(), zmq::SNDMORE)
                                    .and_then(|_| publisher.send(data, 0))
                                {
                                    log::error!("Error sending cached commit message: {e}");
                                }
                            }
                        }
                        t if t == message_topic => {
                            handle_message(data.as_ref(), &inbox_dir);
                        }
                        _ => {
                            log::warn!("Received message on unknown topic");
                        }
                    },
                }
            }
        }
        _ => {
            log::error!(
                "Unsupported transport provider: {}",
                connect_string_parts[0]
            );
        }
    }
}
