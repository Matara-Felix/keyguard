# keyguard

Claude Code hooks that keep API keys and secret files out of the conversation, out of your code and out of git.

Built by Felix Kebaya, https://kebayah.com

## What it does

| When | What keyguard does |
|---|---|
| You send a message | Blocks it if it contains a key. The message is never sent. |
| Claude reads a file | Denies `.env`, `.env.local`, private keys, `~/.aws/credentials`, `~/.ssh/`, `.npmrc` and similar. Asks first for `wp-config.php`. `.env.example` is fine. |
| Claude runs a command | Denies commands that print a secret file (`cat`, `grep`, `source`, a Python or Node one-liner, base64, wildcards such as `.e*`), dump environment variables, or contain a key typed out in full. |
| Claude writes code | Denies a Write or Edit that puts a real key into a file, and tells Claude to read it from the environment instead. |
| Claude stages, commits or pushes | Denies `git add` when it would stage `.env` or a file containing a key, `git commit` when the staged changes contain one, and `git push` when an unpushed commit contains one. |
| A tool returns output | Redacts any key that still shows up, keeping the last four characters so you can tell which key it was. |

Everything it blocks is logged, without the secret, to `.claude/keyguard.log`.

## Install

1. Copy `.claude/hooks/keyguard.mjs` into your project's `.claude/hooks/` folder.
2. Merge `.claude/settings.json` into your project's `.claude/settings.json` (or `~/.claude/settings.json` for every project).
3. Restart Claude Code. Run `/hooks` to confirm the three hooks are listed.

Needs Node 18 or newer on your PATH. No packages to install.

## Configure

Optional `.claude/keyguard.json`:

```json
{
  "allowFiles": ["config/.env.test"],
  "denyFiles": ["config/master.key"],
  "askFiles": ["config/database.yml"]
}
```

## Test

```
node --test tests/keyguard.test.mjs
node tests/live.mjs            # real Claude Code sessions, with keyguard
node tests/live.mjs --without  # the same prompts with no hooks
```

## Limits

keyguard is a seatbelt against accidents, not a sandbox against an attacker. A command built to hide what it reads, for example with command substitution, can get past the command checks. The output redaction then catches keys in their usual formats, but not a secret that has been encoded. If a key has already been pasted, committed or pushed anywhere, rotate it.
