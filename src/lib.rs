use zed_extension_api::{self as zed, settings::LspSettings, LanguageServerId, Result, Worktree};

const SERVER_BINARY: &str = "ansible-vault-lsp";

struct AnsibleVaultExtension;

impl zed::Extension for AnsibleVaultExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<zed::Command> {
        let binary = LspSettings::for_worktree(language_server_id.as_ref(), worktree)
            .ok()
            .and_then(|settings| settings.binary);
        let args = binary
            .as_ref()
            .and_then(|b| b.arguments.clone())
            .unwrap_or_default();
        let mut env = worktree.shell_env();
        if let Some(extra) = binary.as_ref().and_then(|b| b.env.clone()) {
            env.extend(extra);
        }

        let command = binary
            .and_then(|b| b.path)
            .or_else(|| worktree.which(SERVER_BINARY))
            .ok_or_else(|| format!("`{SERVER_BINARY}` not found on PATH"))?;

        Ok(zed::Command { command, args, env })
    }

    fn language_server_initialization_options(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(LspSettings::for_worktree(language_server_id.as_ref(), worktree)
            .ok()
            .and_then(|settings| settings.initialization_options))
    }
}

zed::register_extension!(AnsibleVaultExtension);
