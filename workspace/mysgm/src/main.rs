pub mod agent;
pub mod keys;
pub mod opendht;
pub mod provider;
pub mod state;

use agent::MySgmAgent;

use clap::{Parser, Subcommand};
use hex::encode as hex_encode;
use std::io::{BufRead, stdin};

/// CLI for secure group messsaging agent
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path to a JSON file to read (required)
    state_path: String,
    /// Command to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Resets the agent state
    Reset {
        /// Optional identifier to use in generating agent id
        #[arg(long, default_value = "agent")]
        pid_label: String,
    },
    /// Get the agent's own id
    GetSelf {},
    /// List all groups the agent is part of
    ListGroups {},
    /// List all agents the agent knows about
    ListAgents {},
    /// Create a new group
    CreateGroup {
        /// Optional label for the new group
        #[arg(long, default_value = "group")]
        gid_label: String,
    },
    Advertise {},
    Update {},
    ExportSecret {
        /// Group to export secret for
        #[arg(long)]
        gid: String,
        /// Label for the exported secret
        #[arg(long)]
        exporter_label: String,
        /// Length for the exported secret
        #[arg(long)]
        exporter_length: usize,
    },
    AddToGroup {
        /// Group to add agents to
        #[arg(long)]
        gid: String,
    },
    ListMembers {
        /// Group to list members
        #[arg(long)]
        gid: String,
    },
}

fn main() {
    pretty_env_logger::init();
    log::debug!("Parsing command-line arguments");
    let args = CliArgs::parse();
    log::debug!("Parsed command-line arguments");
    log::info!("Command-line arguments: {args:?}");
    log::info!("Path to agent state: {}", args.state_path);
    log::info!("Command to process: {:?}", args.command);
    match &args.command {
        Commands::Reset { pid_label } => {
            log::debug!("Creating new state");
            let new_agent = MySgmAgent::new(pid_label).unwrap();
            log::debug!("Created new agent state");
            log::info!("New agent state: {new_agent:?}");
            println!("{}", new_agent.credential_str());
            log::debug!("Attempting to write fresh state to disk");
            new_agent.save(&args.state_path).unwrap();
            log::debug!("Wrote fresh state to disk");
        }
        Commands::GetSelf {} => {
            log::debug!("Attempting to load state from file");
            let agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state: {agent:?}");
            println!("{}", agent.credential_str());
        }
        Commands::ListGroups {} => {
            log::debug!("Attempting to load state from file");
            let agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state: {agent:?}");
            for gid in agent.group_ids() {
                println!("{gid}");
            }
        }
        Commands::ListAgents {} => {
            log::debug!("Attempting to load state from file");
            let agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state: {agent:?}");
            for pid in agent.agent_ids() {
                println!("{pid}");
            }
        }
        Commands::CreateGroup { gid_label } => {
            log::debug!("Attempting to load state from file");
            let mut agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state before: {agent:?}");
            log::debug!("Attempting to create new group");
            log::info!("Group label to use for new group: {gid_label}");
            println!("{}", agent.create_group(gid_label).unwrap());
            log::debug!("Created new group");
            log::info!("Agent state after: {agent:?}");
            log::debug!("Attempting to write state back to disk");
            agent.save(&args.state_path).unwrap();
            log::debug!("Wrote state to disk");
        }
        Commands::Advertise {} => {
            log::debug!("Attempting to load state from file");
            let mut agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state before: {agent:?}");
            log::debug!("Attempting to advertise new key package");
            agent.advertise().unwrap();
            log::debug!("Advertised new key package");
            log::info!("Agent state after: {agent:?}");
            log::debug!("Attempting to write state back to disk");
            agent.save(&args.state_path).unwrap();
            log::debug!("Wrote state to disk");
        }
        Commands::Update {} => {
            log::debug!("Attempting to load state from file");
            let mut agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state before: {agent:?}");
            log::debug!("Fetching any new key packages");
            loop {
                match agent.process_next_key_package() {
                    Err(e) => {
                        if e.to_string() == "NoNewKeyPackages" {
                            log::debug!("Found empty slot");
                            break;
                        } else {
                            log::error!("Failed to get package: {e}");
                        }
                    }
                    Ok(()) => {
                        log::debug!("Successfully downloaded key package");
                    }
                }
            }
            log::debug!("Done fetching key packages");
            log::debug!("Fetching any new welcome messages");
            loop {
                match agent.process_next_welcome_message() {
                    Err(e) => {
                        if e.to_string() == "NoNewWelcomeMessages" {
                            log::debug!("Found empty slot");
                            break;
                        } else {
                            log::error!("Failed to get welcome message: {e}");
                        }
                    }
                    Ok(()) => {
                        log::debug!("Successfully downloaded welcome message");
                    }
                }
            }
            log::debug!("Done fetching welcome messages");
            log::info!("Agent state after: {agent:?}");
            log::debug!("Attempting to write state back to disk");
            agent.save(&args.state_path).unwrap();
            log::debug!("Wrote state to disk");
        }
        Commands::ExportSecret {
            gid,
            exporter_label,
            exporter_length,
        } => {
            log::debug!("Attempting to load state from file");
            let agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state: {agent:?}");
            println!(
                "{}",
                hex_encode(
                    agent
                        .exporter(gid, exporter_label, &[], *exporter_length)
                        .unwrap()
                )
            );
        }
        Commands::AddToGroup { gid } => {
            log::debug!("Attempting to load state from file");
            let mut agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state before: {agent:?}");
            log::info!("Group for adding agents: {}", &gid);
            let handle = stdin().lock();
            log::debug!("Reading lines from stdin as agents to add");
            let mut pids = Vec::new();
            for line in handle.lines() {
                match line {
                    Ok(l) => {
                        log::info!("Agent id: {l}");
                        pids.push(l);
                    }
                    Err(e) => {
                        log::error!("Error reading line: {e}");
                        break;
                    }
                }
            }
            let pid_strs: Vec<&str> = pids.iter().map(String::as_str).collect();
            agent.add_to_group(gid, &pid_strs).unwrap();
            log::info!("Agent state after: {agent:?}");
            log::debug!("Attempting to write state back to disk");
            agent.save(&args.state_path).unwrap();
            log::debug!("Wrote state to disk");
        } 
        Commands::ListMembers { gid } => {
            log::debug!("Attempting to load state from file");
            let agent = MySgmAgent::load(&args.state_path).unwrap();
            log::debug!("Loaded agent state");
            log::info!("Agent state: {agent:?}");
            for member in agent.group_members(gid).unwrap() {
                println!("{member}");
            }
        }
            
        /*

                  "group_add" => {
                      log::info!("Group for adding agents: {}", &args.gid);
                      let handle = stdin().lock();
                      log::debug!("Reading lines from stdin as agents to add");
                      let mut pids = Vec::new();
                      for line in handle.lines() {
                          match line {
                              Ok(l) => {
                                  log::info!("Agent id: {l}");
                                  pids.push(l);
                              }
                              Err(e) => {
                                  log::error!("Error reading line: {e}");
                                  break;
                              }
                          }
                      }
                      let pid_strs: Vec<&str> = pids.iter().map(String::as_str).collect();
                      agent.add_to_group(&args.gid, &pid_strs).unwrap();
                  }
              }
          }
              */
    }
    log::debug!("DONE!");
}
