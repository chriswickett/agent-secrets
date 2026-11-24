# agent-secrets

Gives each Claude Code session its own client's 1Password service account, after one Touch ID approval per session.

## The problem

If you work for several clients, your coding agents need each client's secrets, and the agents for one client shouldn't be able to reach another client's secrets without you knowing. Neither of the usual setups manages both:

- **1Password's desktop app integration** asks for Touch ID on every command an agent runs, because it approves one terminal session at a time and every command Claude Code runs is a new one.
- **Service account tokens** never prompt. But they sit on your Mac, where any agent can quietly read every client's token.

agent-secrets asks once per Claude session, on the first use, and the prompt names the client. After that, the session's agents can use that client's secrets with no more prompts. If an agent tries another client's secrets, that brings up a new prompt naming the other client.

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
