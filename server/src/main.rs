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
    eprintln!("ansible-vault-lsp {} started", env!("CARGO_PKG_VERSION"));

    for message in &connection.receiver {
        trace("<-", &message);
        if let Message::Request(request) = &message {
            if connection.handle_shutdown(request)? {
                break;
            }
        }
        for outgoing in server.handle(message) {
            trace("->", &outgoing);
            connection.sender.send(outgoing)?;
        }
    }
    // The writer thread only stops once every sender is dropped.
    drop(connection);
    io_threads.join()?;
    Ok(())
}

/// Logs message names to stderr (shown in Zed's language server logs).
/// Never logs params or results: they may contain secrets.
fn trace(direction: &str, message: &Message) {
    match message {
        Message::Request(request) if request.method == "textDocument/codeAction" => {
            let range = &request.params["range"];
            eprintln!(
                "{direction} {} #{} range {}:{}-{}:{} only {}",
                request.method,
                request.id,
                range["start"]["line"],
                range["start"]["character"],
                range["end"]["line"],
                range["end"]["character"],
                request.params["context"]["only"]
            )
        }
        Message::Request(request) => eprintln!("{direction} {} #{}", request.method, request.id),
        Message::Notification(notification) => eprintln!("{direction} {}", notification.method),
        Message::Response(response) => match &response.response_result {
            Ok(serde_json::Value::Array(items)) => {
                eprintln!(
                    "{direction} response #{} ({} items)",
                    response.id,
                    items.len()
                )
            }
            Ok(_) => eprintln!("{direction} response #{}", response.id),
            Err(error) => eprintln!("{direction} error #{}: {}", response.id, error.message),
        },
    }
}
