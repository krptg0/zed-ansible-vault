use std::fs;

use zed_extension_api::{
    self as zed, settings::LspSettings, Architecture, DownloadedFileType, GithubReleaseOptions,
    LanguageServerId, LanguageServerInstallationStatus, Os, Result, Worktree,
};

const SERVER_BINARY: &str = "ansible-vault-lsp";
const REPOSITORY: &str = "krptg0/zed-ansible-vault";

#[derive(Default)]
struct AnsibleVaultExtension {
    cached_binary_path: Option<String>,
}

impl AnsibleVaultExtension {
    /// PATH first (`cargo install`), then the cached download, then the
    /// latest GitHub release, falling back to an older download when offline.
    fn server_binary_path(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<String> {
        if let Some(path) = worktree.which(SERVER_BINARY) {
            return Ok(path);
        }
        if let Some(path) = &self.cached_binary_path {
            if is_file(path) {
                return Ok(path.clone());
            }
        }

        let path = match download_latest(language_server_id) {
            Ok(path) => path,
            Err(error) => previously_downloaded().ok_or_else(|| {
                zed::set_language_server_installation_status(
                    language_server_id,
                    &LanguageServerInstallationStatus::Failed(error.clone()),
                );
                error
            })?,
        };
        self.cached_binary_path = Some(path.clone());
        Ok(path)
    }
}

impl zed::Extension for AnsibleVaultExtension {
    fn new() -> Self {
        Self::default()
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
        let mut env = match zed::current_platform().0 {
            Os::Mac | Os::Linux => worktree.shell_env(),
            Os::Windows => Vec::new(),
        };
        if let Some(extra) = binary.as_ref().and_then(|b| b.env.clone()) {
            env.extend(extra);
        }

        let command = match binary.and_then(|b| b.path) {
            Some(path) => path,
            None => self.server_binary_path(language_server_id, worktree)?,
        };
        Ok(zed::Command { command, args, env })
    }

    fn language_server_initialization_options(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(
            LspSettings::for_worktree(language_server_id.as_ref(), worktree)
                .ok()
                .and_then(|settings| settings.initialization_options),
        )
    }
}

fn download_latest(language_server_id: &LanguageServerId) -> Result<String> {
    zed::set_language_server_installation_status(
        language_server_id,
        &LanguageServerInstallationStatus::CheckingForUpdate,
    );
    let release = zed::latest_github_release(
        REPOSITORY,
        GithubReleaseOptions {
            require_assets: true,
            pre_release: false,
        },
    )?;

    let (os, arch) = zed::current_platform();
    let target = match (os, arch) {
        (Os::Mac, Architecture::Aarch64) => "aarch64-apple-darwin",
        (Os::Mac, Architecture::X8664) => "x86_64-apple-darwin",
        (Os::Linux, Architecture::Aarch64) => "aarch64-unknown-linux-musl",
        (Os::Linux, Architecture::X8664) => "x86_64-unknown-linux-musl",
        (Os::Windows, Architecture::X8664) => "x86_64-pc-windows-msvc",
        _ => {
            return Err(format!(
                "{SERVER_BINARY} has no prebuilt binary for this platform; install it on PATH"
            ))
        }
    };
    let (extension, file_type) = match os {
        Os::Windows => ("zip", DownloadedFileType::Zip),
        Os::Mac | Os::Linux => ("tar.gz", DownloadedFileType::GzipTar),
    };
    let asset_name = format!("{SERVER_BINARY}-{target}.{extension}");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| format!("release {} has no asset {asset_name}", release.version))?;

    let version_dir = format!("{SERVER_BINARY}-{}", release.version);
    let binary_path = binary_in(&version_dir, os);
    if !is_file(&binary_path) {
        zed::set_language_server_installation_status(
            language_server_id,
            &LanguageServerInstallationStatus::Downloading,
        );
        if let Err(error) = zed::download_file(&asset.download_url, &version_dir, file_type) {
            fs::remove_dir_all(&version_dir).ok();
            return Err(format!("failed to download {asset_name}: {error}"));
        }
        zed::make_file_executable(&binary_path)?;
        remove_other_versions(&version_dir);
    }
    zed::set_language_server_installation_status(
        language_server_id,
        &LanguageServerInstallationStatus::None,
    );
    Ok(binary_path)
}

fn binary_in(version_dir: &str, os: Os) -> String {
    match os {
        Os::Windows => format!("{version_dir}/{SERVER_BINARY}.exe"),
        Os::Mac | Os::Linux => format!("{version_dir}/{SERVER_BINARY}"),
    }
}

/// The extension work directory only ever holds downloaded server versions.
fn remove_other_versions(keep: &str) {
    let Ok(entries) = fs::read_dir(".") else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_str() != Some(keep) {
            fs::remove_dir_all(entry.path()).ok();
        }
    }
}

fn previously_downloaded() -> Option<String> {
    let os = zed::current_platform().0;
    let mut dirs: Vec<String> = fs::read_dir(".")
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(&format!("{SERVER_BINARY}-")))
        .collect();
    dirs.sort();
    dirs.into_iter()
        .rev()
        .map(|dir| binary_in(&dir, os))
        .find(|path| is_file(path))
}

fn is_file(path: &str) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

zed::register_extension!(AnsibleVaultExtension);
