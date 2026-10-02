//! Cross-checks our envelopes against the real `ansible-vault` binary.
//! Skipped when `ansible-vault` is not on PATH, unless REQUIRE_ANSIBLE_VAULT is set.

use std::process::{Command, Stdio};

use ansible_vault_lsp::vault::{self, Secret, DEFAULT_VAULT_ID};

const PASSWORD: &str = "test-password-123";

fn ansible_vault_available() -> bool {
    Command::new("ansible-vault")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn ansible_decrypt(envelope: &str, vault_id_arg: Option<&str>) -> String {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("pw");
    let vault_file = dir.path().join("value.vault");
    std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
    std::fs::write(&vault_file, envelope).unwrap();

    let mut cmd = Command::new("ansible-vault");
    cmd.arg("decrypt").arg("--output").arg("-").arg(&vault_file);
    match vault_id_arg {
        Some(id) => cmd
            .arg("--vault-id")
            .arg(format!("{id}@{}", password_file.display())),
        None => cmd.arg("--vault-password-file").arg(&password_file),
    };
    let output = cmd.stdin(Stdio::null()).output().unwrap();
    assert!(
        output.status.success(),
        "ansible-vault failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn ansible_vault_decrypts_our_envelopes() {
    if !ansible_vault_available() {
        // CI sets REQUIRE_ANSIBLE_VAULT so the cross-check can't silently vanish.
        assert!(
            std::env::var_os("REQUIRE_ANSIBLE_VAULT").is_none(),
            "REQUIRE_ANSIBLE_VAULT is set but ansible-vault is not on PATH"
        );
        eprintln!("ansible-vault not found on PATH: cross-check skipped");
        return;
    }
    for plaintext in [
        "hello",
        "multi\nline\nvalue\n",
        "pässwörd €🔑",
        "exactly16bytes!!",
    ] {
        let envelope = vault::encrypt(
            plaintext.as_bytes(),
            &Secret::new(DEFAULT_VAULT_ID, PASSWORD),
        );
        assert_eq!(ansible_decrypt(&envelope, None), plaintext);
    }
    let envelope = vault::encrypt(b"hello", &Secret::new("dev", PASSWORD));
    assert_eq!(ansible_decrypt(&envelope, Some("dev")), "hello");
}
