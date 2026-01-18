use clap::{Parser, Subcommand};
use cli_table::{format::Justify, print_stdout, Cell, Style, Table};
use crossterm::{
    cursor,
    terminal::{Clear, ClearType},
    ExecutableCommand,
};
use ocserv_rs::control::{ControlCommand, UserSessionInfo};
use std::io::{stdout, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to control socket
    #[arg(short, long, default_value = "/var/run/ocserv-rs.sock")]
    socket_path: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show active users
    #[command(name = "show", subcommand)]
    Show(ShowCommands),
    /// Watch active users (auto-refresh)
    #[command(name = "watch", subcommand)]
    Watch(WatchCommands),
}

#[derive(Subcommand)]
enum ShowCommands {
    /// Show connected users
    Users,
}

#[derive(Subcommand)]
enum WatchCommands {
    /// Watch connected users
    Users,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Show(ShowCommands::Users) => {
            handle_show_users(&cli.socket_path)?;
        }
        Commands::Watch(WatchCommands::Users) => {
            let mut stdout = stdout();
            // Enter alternate screen? Maybe not, just clear.
            // Using raw mode could be nice but simple clear is enough for a basic watch.

            loop {
                // Clear screen and move cursor to top-left
                stdout.execute(Clear(ClearType::All))?;
                stdout.execute(cursor::MoveTo(0, 0))?;

                println!("Auto-refreshing every 1s (Ctrl+C to quit)\n");

                if let Err(e) = handle_show_users(&cli.socket_path) {
                    println!("Error fetching users: {}", e);
                }

                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    Ok(())
}

fn handle_show_users(socket_path: &PathBuf) -> anyhow::Result<()> {
    // Determine command to send
    let cmd = ControlCommand::ShowUsers;
    let req_json = serde_json::to_string(&cmd)?;

    // Connect to socket
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(req_json.as_bytes())?;
    stream.shutdown(std::net::Shutdown::Write)?;

    // Read response
    let mut resp_json = String::new();
    stream.read_to_string(&mut resp_json)?;

    // Parse response
    let users: Vec<UserSessionInfo> = serde_json::from_str(&resp_json)?;

    if users.is_empty() {
        println!("No active users connected.");
        return Ok(());
    }

    let mut rows = Vec::new();
    for user in users {
        let connected_at = user.connected_at_rfc3339.unwrap_or_else(|| "-".to_string());
        let duration = if let Some(secs) = user.connected_seconds {
            format!("{}s", secs)
        } else {
            "-".to_string()
        };
        let remote_ip = user.remote_ip.unwrap_or_else(|| "-".to_string());

        rows.push(vec![
            user.username.cell(),
            user.vpn_ip.unwrap_or_default().cell(),
            remote_ip.cell(),
            connected_at.cell(),
            duration.cell().justify(Justify::Right),
        ]);
    }

    let table = rows
        .table()
        .title(vec![
            "Username".cell().bold(true),
            "VPN IP".cell().bold(true),
            "Remote IP".cell().bold(true),
            "Connected At".cell().bold(true),
            "Duration".cell().bold(true),
        ])
        .bold(true);

    print_stdout(table)?;

    Ok(())
}
