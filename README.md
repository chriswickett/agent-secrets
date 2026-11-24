# agent-secrets

Gives each Claude Code session its own client's 1Password service account, after one Touch ID approval per session.

## How it works

- `~/.local/bin/op` is a wrapper that runs `agent-secrets op …`.
- agent-secrets walks up the process tree to the Claude process that started the command. The client is looked up in `~/.config/agent-secrets/clients.json` from the folder Claude was launched in. The longest matching folder wins.
- If that client has a token stored, the first `op` call in the session shows a Touch ID prompt naming the folder and client. Later calls in the same session don't prompt.
- It then runs the real `op` with `OP_SERVICE_ACCOUNT_TOKEN` set to that client's token.
- Outside Claude, or for a folder with no stored token, `op` behaves as normal.

Tokens live in the login Keychain under the service `agent-secrets`. Only this binary can read them without a macOS dialog. Approvals are files in `~/Library/Caches/agent-secrets`, each an HMAC of the Claude process ID and start time keyed with the client's token, so they can't be forged and they end when the Claude session ends.

## Setup

```sh
./build.sh
```

Then add each client to `~/.config/agent-secrets/clients.json`. The key names the stored token, and the Touch ID prompt shows `name`:

```json
{
  "acme": { "name": "Acme Ltd", "folder": "~/code/acme" }
}
```

Copy that client's service account token and run this in your own terminal, not from Claude:

```sh
pbpaste | agent-secrets store <key>
```

Keychain trusts the exact binary, so after every rebuild, store each token again.

## Checking

`agent-secrets status`, run from Claude, shows the detected session, client, and whether a token is stored and approved.
