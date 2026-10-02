use std::error::Error;

use ansible_vault_lsp::password::Env;
use ansible_vault_lsp::server::Server;
use lsp_server::{Connection, Message};
use lsp_types::InitializeParams;

fn main() -> Result<(), Box<dyn Error + Sync + Send>> {
    if std::env::args().any(|arg| arg == "--version") {
        println!("ansible-vault-lsp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let (connection, io_threads) = Connection::stdio();
    let capabilities = serde_json::to_value(Server::capabilities())?;
    let params: InitializeParams = serde_json::from_value(connection.initialize(capabilities)?)?;
    let mut server = Server::new(params, Env::from_process());

    for message in &connection.receiver {
        if let Message::Request(request) = &message {
            if connection.handle_shutdown(request)? {
                break;
            }
        }
        for outgoing in server.handle(message) {
            connection.sender.send(outgoing)?;
        }
    }
    io_threads.join()?;
    Ok(())
}
