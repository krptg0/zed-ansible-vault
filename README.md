# Ansible Vault for Zed

Encrypt, decrypt and preview [ansible-vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html)
values without leaving [Zed](https://zed.dev), in the spirit of the VSCode
extension [ansible-vault-inline](https://gitlab.com/wolfmah/vscode-ansible-vault-inline).

- **Hover** an inline `!vault |` value to see it in clear.
- **Decrypt value** in place, edit it, select it, **Encrypt selection** back.
- **Decrypt file** / **Encrypt file** for whole-file vaults.
- A warning stays on every value decrypted during the session until it is
  encrypted again, so a secret is not saved or committed in clear by mistake.

Encryption is implemented natively in Rust (`$ANSIBLE_VAULT;1.1;AES256`, and
`1.2` with a vault id). It is byte-compatible with `ansible-vault` and checked
against it in CI. Python and Ansible are **not** required.

## Usage

Zed extensions cannot add commands, so everything goes through code actions
(`cmd-.` / `ctrl-.`) and hover:

| Where | Action |
|---|---|
| Cursor anywhere on a `!vault \|` block | `cmd-.` → **Ansible Vault: Decrypt value** |
| Some text selected | `cmd-.` → **Ansible Vault: Encrypt selection** |
| File starting with `$ANSIBLE_VAULT;` | `cmd-.` → **Ansible Vault: Decrypt file** |
| Whole buffer selected (`cmd-a`) | `cmd-.` → **Ansible Vault: Encrypt file** |

`cmd-.` is Zed's `editor: toggle code actions`, mapped by keyboard layout: on a
French AZERTY Mac it is `cmd-;` (the `;` key, no shift). The command palette
and the ⚡ indicator in the gutter open the same menu.

Encrypting a selection produces a block like `ansible-vault encrypt_string`,
aligned on the selection:

```yaml
db_password: !vault |
             $ANSIBLE_VAULT;1.1;AES256
             6338346533373665...
```

Decrypting inserts the raw value, exactly like the VSCode extension. That way,
selecting it again and encrypting it gives back an equivalent block. A
multi-line secret becomes valid YAML again once it is re-encrypted.

## Vault password

The password is looked up like `ansible-vault` does. The workspace folder that
contains the file plays the role of the current directory:

1. the `vaultPasswordFile` setting (absolute, `~/…`, or relative to the workspace folder);
2. the `ANSIBLE_VAULT_PASSWORD_FILE` environment variable;
3. `vault_password_file` in the first `ansible.cfg` found:
   - `ANSIBLE_CONFIG`;
   - the nearest `ansible.cfg` between the file and the workspace folder;
   - `~/.ansible.cfg`;
   - `/etc/ansible/ansible.cfg`.

   A relative path is resolved from the directory of that `ansible.cfg`.

Executable password files are run and their output is used. Scripts named
`*-client` receive `--vault-id <id>`. The environment comes from your login
shell, so variables set by direnv are picked up.

Not supported yet: `vault_identity_list` (several vault ids) and encrypted
password files.

## Settings

```jsonc
// settings.json
{
  "lsp": {
    "ansible-vault-lsp": {
      "initialization_options": {
        "vaultPasswordFile": "~/.config/ansible/vault-pass", // optional
        "hover": true // set to false to never show secrets on hover (screen sharing)
      },
      // optional: use your own build instead of the downloaded one
      "binary": { "path": "/path/to/ansible-vault-lsp" }
    }
  }
}
```

Restart the server after a change (`editor: restart language server`).

The server attaches to `YAML`, `Ansible` and `Plain Text` files. Vault files
without an extension (for example `group_vars/all/vault`) have no language in
Zed, so map them explicitly:

```jsonc
{ "file_types": { "Plain Text": ["**/vault"] } }
```

To disable the server for a language:
`"languages": { "Plain Text": { "language_servers": ["!ansible-vault-lsp", "..."] } }`.

## Installation

Install **Ansible Vault** from Zed's extension gallery. Until then, use it as a
dev extension:

1. Install Rust with [rustup](https://rustup.rs).
2. `git clone https://github.com/krptg0/zed-ansible-vault`
3. In Zed, run `zed: install dev extension` and select the cloned folder.

On first use, the extension downloads the `ansible-vault-lsp` binary for your
platform from the [releases](https://github.com/krptg0/zed-ansible-vault/releases).
An `ansible-vault-lsp` already on `PATH` takes precedence:
`cargo install --git https://github.com/krptg0/zed-ansible-vault ansible-vault-lsp`.

## Development

```sh
cargo test -p ansible-vault-lsp          # unit + LSP scenario tests (+ cross-check if ansible-vault is installed)
cargo install --path server              # put your build on PATH, then restart the language server in Zed
server/tests/fixtures/generate.sh        # regenerate fixtures with the real ansible-vault
```

Server logs are under `dev: open language server logs`.

## License

MIT
