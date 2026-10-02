//! Locates and reads the vault password the way `ansible-vault` does, with the
//! worktree root standing in for Ansible's current working directory.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::vault::{Secret, DEFAULT_VAULT_ID};

const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordError(pub String);

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PasswordError {}

fn err<T>(message: impl Into<String>) -> Result<T, PasswordError> {
    Err(PasswordError(message.into()))
}

/// Process environment, injectable for tests.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub vars: HashMap<String, String>,
    pub home: Option<PathBuf>,
    pub system_cfg: PathBuf,
}

impl Env {
    pub fn from_process() -> Self {
        let vars: HashMap<String, String> = std::env::vars().collect();
        let home = vars
            .get("HOME")
            .or_else(|| vars.get("USERPROFILE"))
            .map(PathBuf::from);
        Self {
            vars,
            home,
            system_cfg: PathBuf::from("/etc/ansible/ansible.cfg"),
        }
    }

    fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// Where the lookup happens: the document being edited and its worktree.
pub struct Context<'a> {
    pub document_dir: &'a Path,
    pub worktree_root: &'a Path,
    /// `vaultPasswordFile` from the server settings.
    pub setting: Option<&'a str>,
    pub env: &'a Env,
}

/// A password file located by [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub path: PathBuf,
    pub vault_id: String,
    /// Human-readable origin, used in error messages.
    pub origin: String,
}

/// Finds the vault password file: setting, then `ANSIBLE_VAULT_PASSWORD_FILE`,
/// then `vault_password_file` from the first `ansible.cfg` found.
pub fn resolve(ctx: &Context) -> Result<Resolved, PasswordError> {
    let cfg = find_ansible_cfg(ctx);
    let cfg_values = match &cfg {
        Some(path) => read_ini_defaults(path)?,
        None => HashMap::new(),
    };
    let vault_id = ctx
        .env
        .var("ANSIBLE_VAULT_IDENTITY")
        .or_else(|| cfg_values.get("vault_identity").map(String::as_str))
        .filter(|id| !id.is_empty())
        .unwrap_or(DEFAULT_VAULT_ID)
        .to_string();

    if let Some(setting) = ctx.setting.filter(|s| !s.trim().is_empty()) {
        let path = expand_path(setting.trim(), ctx.worktree_root, ctx.env);
        return Ok(Resolved {
            path,
            vault_id,
            origin: "setting `vaultPasswordFile`".into(),
        });
    }
    if let Some(value) = ctx.env.var("ANSIBLE_VAULT_PASSWORD_FILE") {
        let path = expand_path(value, ctx.worktree_root, ctx.env);
        return Ok(Resolved {
            path,
            vault_id,
            origin: "ANSIBLE_VAULT_PASSWORD_FILE".into(),
        });
    }
    if let Some(cfg) = &cfg {
        if let Some(value) = cfg_values
            .get("vault_password_file")
            .filter(|v| !v.is_empty())
        {
            let value = value.replace("{{CWD}}", &ctx.worktree_root.to_string_lossy());
            let cfg_dir = cfg.parent().unwrap_or(ctx.worktree_root);
            let path = expand_path(&value, cfg_dir, ctx.env);
            return Ok(Resolved {
                path,
                vault_id,
                origin: cfg.display().to_string(),
            });
        }
    }

    let identity_list = ctx.env.var("ANSIBLE_VAULT_IDENTITY_LIST").is_some()
        || cfg_values
            .get("vault_identity_list")
            .is_some_and(|v| !v.is_empty());
    if identity_list {
        return err("vault_identity_list is not supported yet: set vault_password_file instead");
    }
    let looked_in = match &cfg {
        Some(path) => format!("`vault_password_file` is missing from {}", path.display()),
        None => "no ansible.cfg found".to_string(),
    };
    err(format!(
        "no vault password configured: {looked_in}, ANSIBLE_VAULT_PASSWORD_FILE is unset \
         and the `vaultPasswordFile` setting is empty"
    ))
}

/// Ansible's lookup order, except that the current directory becomes "the
/// nearest `ansible.cfg` between the document and the worktree root".
fn find_ansible_cfg(ctx: &Context) -> Option<PathBuf> {
    if let Some(value) = ctx.env.var("ANSIBLE_CONFIG") {
        let mut path = expand_path(value, ctx.worktree_root, ctx.env);
        if path.is_dir() {
            path.push("ansible.cfg");
        }
        if path.is_file() {
            return Some(path);
        }
    }

    let mut dirs: Vec<&Path> = if ctx.document_dir.starts_with(ctx.worktree_root) {
        ctx.document_dir
            .ancestors()
            .take_while(|d| d.starts_with(ctx.worktree_root))
            .collect()
    } else {
        vec![ctx.document_dir, ctx.worktree_root]
    };
    dirs.dedup();
    for dir in dirs {
        let candidate = dir.join("ansible.cfg");
        if candidate.is_file() && !is_world_writable(dir) {
            return Some(candidate);
        }
    }

    let home_cfg = ctx.env.home.as_ref().map(|home| home.join(".ansible.cfg"));
    home_cfg
        .into_iter()
        .chain([ctx.env.system_cfg.clone()])
        .find(|path| path.is_file())
}

#[cfg(unix)]
fn is_world_writable(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    dir.metadata()
        .is_ok_and(|m| m.permissions().mode() & 0o002 != 0)
}

#[cfg(not(unix))]
fn is_world_writable(_dir: &Path) -> bool {
    false
}

/// Reads `[defaults]` with ConfigParser semantics: case-insensitive keys,
/// `=` or `:` separators, `#`/`;` comment lines, ` ;` inline comments.
fn read_ini_defaults(path: &Path) -> Result<HashMap<String, String>, PasswordError> {
    let text = std::fs::read_to_string(path)
        .or_else(|e| err(format!("cannot read {}: {e}", path.display())))?;
    let mut values = HashMap::new();
    let mut in_defaults = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') {
            in_defaults =
                trimmed.trim_end_matches(']').trim_start_matches('[').trim() == "defaults";
            continue;
        }
        if !in_defaults || line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some(split) = trimmed.find(['=', ':']) else {
            continue;
        };
        let key = trimmed[..split].trim().to_ascii_lowercase();
        let mut value = trimmed[split + 1..].trim();
        if let Some(comment) = value.find(" ;").or_else(|| value.find("\t;")) {
            value = value[..comment].trim_end();
        }
        values.insert(key, value.to_string());
    }
    Ok(values)
}

/// `os.path.expandvars` + `expanduser`, then relative paths join `base`.
fn expand_path(value: &str, base: &Path, env: &Env) -> PathBuf {
    let expanded = expand_vars(value, env);
    let expanded = match (expanded.strip_prefix('~'), &env.home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            format!("{}{rest}", home.display())
        }
        _ => expanded,
    };
    let path = PathBuf::from(expanded);
    let joined = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    normalize(&joined)
}

fn expand_vars(value: &str, env: &Env) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('$') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let (name, consumed) = if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => (&braced[..end], end + 2),
                None => ("", 0),
            }
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (&after[..end], end)
        };
        match env.vars.get(name).filter(|_| !name.is_empty()) {
            Some(val) => out.push_str(val),
            None => out.push_str(&rest[start..start + 1 + consumed]),
        }
        rest = &after[consumed..];
    }
    out.push_str(rest);
    out
}

fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Session cache of passwords, keyed by file and invalidated on modification.
#[derive(Default)]
pub struct PasswordStore {
    cache: HashMap<PathBuf, (Option<SystemTime>, Vec<u8>)>,
}

impl PasswordStore {
    pub fn secrets(&mut self, ctx: &Context) -> Result<Vec<Secret>, PasswordError> {
        let resolved = resolve(ctx)?;
        let mtime = std::fs::metadata(&resolved.path)
            .and_then(|m| m.modified())
            .ok();
        if let Some((cached_mtime, password)) = self.cache.get(&resolved.path) {
            if *cached_mtime == mtime {
                return Ok(vec![Secret::new(resolved.vault_id, password.clone())]);
            }
        }
        let password = read_password(&resolved, ctx.worktree_root)?;
        self.cache
            .insert(resolved.path.clone(), (mtime, password.clone()));
        Ok(vec![Secret::new(resolved.vault_id, password)])
    }

    /// Forgets cached passwords, e.g. after a failed decryption.
    pub fn invalidate(&mut self) {
        self.cache.clear();
    }
}

fn read_password(resolved: &Resolved, cwd: &Path) -> Result<Vec<u8>, PasswordError> {
    let path = &resolved.path;
    let metadata = match std::fs::metadata(path) {
        Ok(m) if m.is_file() => m,
        _ => {
            return err(format!(
                "the vault password file {} (from {}) was not found",
                path.display(),
                resolved.origin
            ))
        }
    };

    if is_executable(&metadata) {
        let output = run_script(resolved, cwd)?;
        let password = trim_matches(&output, b"\r\n").to_vec();
        if password.is_empty() {
            return err(format!(
                "Invalid vault password was provided from script ({})",
                path.display()
            ));
        }
        return Ok(password);
    }

    let content =
        std::fs::read(path).or_else(|e| err(format!("cannot read {}: {e}", path.display())))?;
    let password = trim_matches(&content, b" \t\n\r\x0b\x0c").to_vec();
    if password.is_empty() {
        return err(format!(
            "Invalid vault password was provided from file ({})",
            path.display()
        ));
    }
    if password.starts_with(b"$ANSIBLE_VAULT") {
        return err(format!(
            "encrypted vault password files are not supported ({})",
            path.display()
        ));
    }
    Ok(password)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Runs a password script; `*-client` scripts receive `--vault-id <id>`.
fn run_script(resolved: &Resolved, cwd: &Path) -> Result<Vec<u8>, PasswordError> {
    let path = &resolved.path;
    let is_client = path
        .file_stem()
        .is_some_and(|stem| stem.to_string_lossy().ends_with("-client"));
    let mut command = Command::new(path);
    if is_client {
        command.arg("--vault-id").arg(&resolved.vault_id);
    }
    let mut child = command
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .or_else(|e| {
            err(format!(
                "cannot run vault password script {}: {e}",
                path.display()
            ))
        })?;

    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).map(|_| buf)
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf).map(|_| buf)
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > SCRIPT_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return err(format!(
                    "vault password script {} timed out after {}s",
                    path.display(),
                    SCRIPT_TIMEOUT.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                return err(format!(
                    "vault password script {} failed: {e}",
                    path.display()
                ))
            }
        }
    };
    let stdout = out_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let stderr = err_reader
        .join()
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();

    if !status.success() {
        let code = status
            .code()
            .map_or("signal".to_string(), |c| c.to_string());
        return err(format!(
            "vault password script {} returned non-zero ({code}): {}",
            path.display(),
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    Ok(stdout)
}

fn trim_matches<'a>(bytes: &'a [u8], set: &[u8]) -> &'a [u8] {
    let start = bytes
        .iter()
        .position(|b| !set.contains(b))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !set.contains(b))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        dir: tempfile::TempDir,
        env: Env,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let env = Env {
                vars: HashMap::new(),
                home: Some(dir.path().join("home")),
                system_cfg: dir.path().join("etc/ansible.cfg"),
            };
            fs::create_dir_all(dir.path().join("repo/inventory/host_vars")).unwrap();
            fs::create_dir_all(dir.path().join("home")).unwrap();
            Self { dir, env }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }

        fn write(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.path(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, content).unwrap();
            path
        }

        #[cfg(unix)]
        fn script(&self, rel: &str, body: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = self.write(rel, &format!("#!/bin/sh\n{body}\n"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn resolve(&self, setting: Option<&str>) -> Result<Resolved, PasswordError> {
            let doc = self.path("repo/inventory/host_vars");
            let root = self.path("repo");
            resolve(&Context {
                document_dir: &doc,
                worktree_root: &root,
                setting,
                env: &self.env,
            })
        }

        fn password(&self, setting: Option<&str>) -> Result<Vec<u8>, PasswordError> {
            let doc = self.path("repo/inventory/host_vars");
            let root = self.path("repo");
            let ctx = Context {
                document_dir: &doc,
                worktree_root: &root,
                setting,
                env: &self.env,
            };
            PasswordStore::default()
                .secrets(&ctx)
                .map(|s| s[0].password.clone())
        }
    }

    #[test]
    fn cfg_relative_path_resolves_from_cfg_directory() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=.vaultpass\n",
        );
        let resolved = f.resolve(None).unwrap();
        assert_eq!(resolved.path, f.path("repo/.vaultpass"));
        assert_eq!(resolved.vault_id, "default");
    }

    #[test]
    fn nearest_cfg_wins_when_walking_up() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=root.pw\n",
        );
        f.write(
            "repo/inventory/ansible.cfg",
            "[defaults]\nvault_password_file=near.pw\n",
        );
        assert_eq!(
            f.resolve(None).unwrap().path,
            f.path("repo/inventory/near.pw")
        );
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_directory_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=root.pw\n",
        );
        f.write(
            "repo/inventory/ansible.cfg",
            "[defaults]\nvault_password_file=near.pw\n",
        );
        fs::set_permissions(f.path("repo/inventory"), fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(f.resolve(None).unwrap().path, f.path("repo/root.pw"));
    }

    #[test]
    fn ini_parsing_follows_configparser() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "# comment\n[ssh_connection]\nvault_password_file=wrong\n[defaults]\n; note\n\
             Vault_Password_File : ~/secret.pw ; inline comment\n",
        );
        assert_eq!(f.resolve(None).unwrap().path, f.path("home/secret.pw"));
    }

    #[test]
    fn env_var_beats_cfg_and_is_relative_to_worktree_root() {
        let mut f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=cfg.pw\n",
        );
        f.env
            .vars
            .insert("ANSIBLE_VAULT_PASSWORD_FILE".into(), "env.pw".into());
        assert_eq!(f.resolve(None).unwrap().path, f.path("repo/env.pw"));
    }

    #[cfg(unix)] // absolute paths without a drive letter
    #[test]
    fn setting_beats_everything() {
        let mut f = Fixture::new();
        f.env
            .vars
            .insert("ANSIBLE_VAULT_PASSWORD_FILE".into(), "env.pw".into());
        f.env.vars.insert("SECRETS".into(), "/opt/secrets".into());
        assert_eq!(
            f.resolve(Some("$SECRETS/pw")).unwrap().path,
            PathBuf::from("/opt/secrets/pw")
        );
    }

    #[test]
    fn ansible_config_env_accepts_file_or_directory() {
        let mut f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=local.pw\n",
        );
        f.write(
            "elsewhere/ansible.cfg",
            "[defaults]\nvault_password_file=other.pw\n",
        );
        f.env.vars.insert(
            "ANSIBLE_CONFIG".into(),
            f.path("elsewhere").display().to_string(),
        );
        assert_eq!(f.resolve(None).unwrap().path, f.path("elsewhere/other.pw"));
        f.env.vars.insert(
            "ANSIBLE_CONFIG".into(),
            f.path("elsewhere/ansible.cfg").display().to_string(),
        );
        assert_eq!(f.resolve(None).unwrap().path, f.path("elsewhere/other.pw"));
    }

    #[cfg(unix)] // absolute paths without a drive letter
    #[test]
    fn falls_back_to_home_then_system_cfg() {
        let f = Fixture::new();
        f.write(
            "etc/ansible.cfg",
            "[defaults]\nvault_password_file=/etc/pw\n",
        );
        assert_eq!(f.resolve(None).unwrap().path, PathBuf::from("/etc/pw"));
        f.write(
            "home/.ansible.cfg",
            "[defaults]\nvault_password_file=~/home.pw\n",
        );
        assert_eq!(f.resolve(None).unwrap().path, f.path("home/home.pw"));
    }

    #[test]
    fn vault_identity_labels_the_secret() {
        let mut f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=pw\nvault_identity=team\n",
        );
        assert_eq!(f.resolve(None).unwrap().vault_id, "team");
        f.env
            .vars
            .insert("ANSIBLE_VAULT_IDENTITY".into(), "ops".into());
        assert_eq!(f.resolve(None).unwrap().vault_id, "ops");
    }

    #[test]
    fn missing_configuration_is_explained() {
        let f = Fixture::new();
        let message = f.resolve(None).unwrap_err().0;
        assert!(message.contains("no ansible.cfg found"), "{message}");
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_identity_list=dev@dev.pw\n",
        );
        let message = f.resolve(None).unwrap_err().0;
        assert!(
            message.contains("vault_identity_list is not supported"),
            "{message}"
        );
    }

    #[test]
    fn password_file_is_stripped_of_surrounding_whitespace() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=.vaultpass\n",
        );
        f.write("repo/.vaultpass", "  test-password-123 \t\n\n");
        assert_eq!(f.password(None).unwrap(), b"test-password-123");
    }

    #[test]
    fn empty_or_missing_password_file_is_an_error() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=.vaultpass\n",
        );
        assert!(f.password(None).unwrap_err().0.contains("was not found"));
        f.write("repo/.vaultpass", " \n");
        assert!(f
            .password(None)
            .unwrap_err()
            .0
            .contains("Invalid vault password"));
    }

    #[cfg(unix)]
    #[test]
    fn executable_password_file_runs_and_keeps_inner_spaces() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=pw.sh\n",
        );
        f.script("repo/pw.sh", "printf ' spaced pw \\r\\n'");
        assert_eq!(f.password(None).unwrap(), b" spaced pw ");
    }

    #[cfg(unix)]
    #[test]
    fn client_script_receives_vault_id() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=vault-client.sh\n",
        );
        f.script("repo/vault-client.sh", "echo \"pw-for-$2\"");
        assert_eq!(f.password(None).unwrap(), b"pw-for-default");
    }

    #[cfg(unix)]
    #[test]
    fn failing_script_reports_stderr() {
        let f = Fixture::new();
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=pw.sh\n",
        );
        f.script("repo/pw.sh", "echo 'vault locked' >&2; exit 3");
        let message = f.password(None).unwrap_err().0;
        assert!(
            message.contains("non-zero (3)") && message.contains("vault locked"),
            "{message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_caches_until_the_file_changes() {
        let f = Fixture::new();
        let counter = f.path("runs");
        f.write(
            "repo/ansible.cfg",
            "[defaults]\nvault_password_file=pw.sh\n",
        );
        f.script(
            "repo/pw.sh",
            &format!("echo run >> '{}'; echo pw", counter.display()),
        );
        let doc = f.path("repo/inventory/host_vars");
        let root = f.path("repo");
        let ctx = Context {
            document_dir: &doc,
            worktree_root: &root,
            setting: None,
            env: &f.env,
        };
        let mut store = PasswordStore::default();
        store.secrets(&ctx).unwrap();
        store.secrets(&ctx).unwrap();
        assert_eq!(fs::read_to_string(&counter).unwrap().lines().count(), 1);
        store.invalidate();
        store.secrets(&ctx).unwrap();
        assert_eq!(fs::read_to_string(&counter).unwrap().lines().count(), 2);
    }
}
