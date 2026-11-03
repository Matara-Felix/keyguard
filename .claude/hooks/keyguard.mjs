#!/usr/bin/env node
/**
 * keyguard: Claude Code hooks that keep API keys and secret files away from the model.
 *
 *   UserPromptSubmit  block a message that contains a key, before it is sent
 *   PreToolUse        block reading secret files, dumping env vars, writing keys
 *                     into code, and committing or pushing secrets
 *   PostToolUse       redact any key that still shows up in a tool's output
 *
 * No dependencies. Node 18+. Built by Felix Kebaya, https://kebayah.com
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------------------------------------------------------------- what a secret looks like

/** Known key formats. Order matters: specific prefixes before the generic sk- one. */
export const KEY_PATTERNS = [
	{ name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
	{ name: 'OpenRouter API key', re: /\bsk-or-v1-[A-Za-z0-9]{32,}/g },
	{ name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
	{ name: 'Stripe live key', re: /\b[sr]k_live_[A-Za-z0-9]{20,}/g },
	{ name: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
	{ name: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})/g },
	{ name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
	{ name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
	{ name: 'private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|$)/g },
];

/** api_key = "..." style assignments with a value that looks random, not a placeholder. */
const ASSIGNMENT = /\b([A-Za-z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d|auth)[A-Za-z0-9_]*)\b["']?\s*[:=]\s*["']([^"'\s]{16,})["']/gi;
const ENV_LINE = /(?:^|[\s:;])(?:export\s+)?([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*)\s*=\s*([^\s"'#;]{8,})/gim;
const PLACEHOLDER = /your|example|changeme|placeholder|dummy|sample|xxxx|\*\*\*|<|>|\$\{|process\.env|getenv|os\.environ|env\(/i;

function entropy(s) {
	const counts = {};
	for (const c of s) counts[c] = (counts[c] || 0) + 1;
	return Object.values(counts).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

/** Every secret in a piece of text: [{ name, value, index }]. */
export function findSecrets(text) {
	if (typeof text !== 'string' || text.length < 16) return [];
	const found = [];
	const seen = new Set();
	for (const { name, re } of KEY_PATTERNS) {
		for (const m of text.matchAll(re)) {
			if ([...seen].some((v) => v.includes(m[0]))) continue; // already caught by a more specific pattern
			seen.add(m[0]);
			found.push({ name, value: m[0], index: m.index });
		}
	}
	for (const m of text.matchAll(ASSIGNMENT)) {
		const value = m[2];
		if (seen.has(value) || PLACEHOLDER.test(value)) continue;
		if (entropy(value) < 3.5 || !/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) continue;
		seen.add(value);
		found.push({ name: `value of ${m[1]}`, value, index: m.index + m[0].indexOf(value) });
	}
	// .env style lines, including inside grep output ("./.env:2:DB_PASSWORD=..."). The name says
	// it is a secret, so the value is treated as one however random it looks.
	for (const m of text.matchAll(ENV_LINE)) {
		const value = m[2];
		if (seen.has(value) || [...seen].some((v) => v.includes(value)) || PLACEHOLDER.test(value) || /^\$|^\d+$|^(true|false|null)$/i.test(value)) continue;
		seen.add(value);
		found.push({ name: `value of ${m[1]}`, value, index: m.index + m[0].lastIndexOf(value) });
	}
	return found;
}

/** "a OpenRouter key" reads badly. */
export function a(name) {
	return (/^[aeiou]/i.test(name) ? 'an ' : 'a ') + name;
}

/** Show enough to recognise a key, never enough to use it. */
export function mask(value) {
	if (value.startsWith('-----BEGIN')) return '[private key]';
	const prefix = (value.match(/^(sk-ant-|sk-or-v1-|sk-proj-|sk-|[sr]k_live_|AKIA|ASIA|gh[pousr]_|github_pat_|xox[abprs]-|AIza)/) || [''])[0];
	return `${prefix}…${value.slice(-4)}`;
}

export function redact(text) {
	let out = text;
	for (const s of findSecrets(text)) out = out.split(s.value).join(`[REDACTED ${s.name} ${mask(s.value)}]`);
	return out;
}

// ---------------------------------------------------------------- what a secret file looks like

const SAFE_ENV_SUFFIX = /\.(example|sample|template|dist|defaults)$/i;

/** 'deny' for files that hold secrets, 'ask' for files that mix secrets with code, or null. */
export function secretFileVerdict(p, config = {}) {
	if (!p) return null;
	const norm = String(p).replace(/\\/g, '/');
	const base = norm.split('/').pop();
	if ((config.allowFiles || []).some((a) => norm.endsWith(a))) return null;
	if (/^\.env(\..+)?$/i.test(base) && !SAFE_ENV_SUFFIX.test(base)) return 'deny';
	if (/\.(pem|key|p12|pfx|jks|keystore)$/i.test(base)) return 'deny';
	if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(base)) return 'deny';
	if (/^(\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials\.json|secrets\.(json|ya?ml|toml)|service-account.*\.json)$/i.test(base)) return 'deny';
	if (/(^|\/)\.aws\/credentials$|(^|\/)\.ssh\//.test(norm)) return 'deny';
	if ((config.denyFiles || []).some((d) => norm.endsWith(d))) return 'deny';
	if (base === 'wp-config.php' || (config.askFiles || []).some((a) => norm.endsWith(a))) return 'ask';
	return null;
}

// ---------------------------------------------------------------- shell commands

/** Commands that touch a secret file without printing what is inside it. */
const SAFE_WITH_SECRET_FILE = /^(ls|test|\[|stat|touch|chmod|git\s+(check-ignore|rm\s+--cached|ls-files))\b/;
const ENV_DUMP = /(^|[;&|]\s*)(env|printenv|export\s+-p|set|declare\s+-x)\s*($|[;&|>])/;
const ENV_ECHO = /\$\{?[A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z_]*\}?/i;

function segments(command) {
	return command.split(/\s*(?:&&|\|\||;|\||\n)\s*/).map((s) => s.trim()).filter(Boolean);
}

/** Every path-like word in a segment, including ones inside quotes or code strings. */
function pathWords(seg) {
	return seg.match(/[A-Za-z0-9_~./\\-]*[A-Za-z0-9_.-]+/g) || [];
}

export function checkCommand(command, cwd, config = {}) {
	for (const seg of segments(command)) {
		const secretWords = pathWords(seg).filter((w) => secretFileVerdict(w, config) === 'deny');
		if (secretWords.length && !SAFE_WITH_SECRET_FILE.test(seg)) {
			const cp = seg.match(/^(cp|mv)\s+(?:-\S+\s+)*(\S+)/);
			if (!(cp && secretFileVerdict(cp[2], config) !== 'deny')) {
				return `This command would read ${secretWords[0]}, which holds secrets. Ask the user for the variable name you need, and reference it from the environment in code (process.env.NAME, getenv('NAME')).`;
			}
		}
		// Wildcards that could expand to .env: cat .e*, base64 .en?, cat *env*
		if (!SAFE_WITH_SECRET_FILE.test(seg) && /(^|[\s'"\/=])(\.e[\w.]*[*?[]|\.[*?][\w*?]*|\*\.?env\*?|\*env[\w.]*)(?=$|[\s'";)])/.test(seg)) {
			return 'This command uses a wildcard that could match .env, which holds secrets. Name the files you need instead.';
		}
		if (ENV_DUMP.test(seg) || (/^printenv\s+\w*(KEY|TOKEN|SECRET|PASS)/i.test(seg))) {
			return 'This command prints environment variables, which can include API keys. Check a specific variable is set with: test -n "$NAME" && echo set';
		}
		if (/^(echo|printf|print)\b/.test(seg) && ENV_ECHO.test(seg)) {
			return 'This command would print a secret environment variable. Check it is set with: test -n "$NAME" && echo set';
		}
	}

	const keys = findSecrets(command);
	if (keys.length) {
		return `This command contains ${a(keys[0].name)} (${mask(keys[0].value)}) written out in full. Put it in .env and read it from the environment instead.`;
	}

	if (/\bgit\s+add\s/.test(command) || /\bgit\s+commit\b.*\s-(a\w*|-all)\b/.test(command)) {
		const reason = checkGitAdd(command, cwd, config);
		if (reason) return reason;
	}
	if (/\bgit\s+commit\b/.test(command)) {
		const reason = checkStaged(cwd);
		if (reason) return reason;
	}
	if (/\bgit\s+push\b/.test(command)) {
		const reason = checkUnpushed(cwd);
		if (reason) return reason;
	}
	return null;
}

// ---------------------------------------------------------------- git

function git(cwd, args) {
	try {
		return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 32 * 1024 * 1024 });
	} catch {
		return null;
	}
}

/** git add . / -A / a named file: would it stage a secret file that is not ignored? */
function checkGitAdd(command, cwd, config) {
	const status = git(cwd, ['status', '--porcelain', '--untracked-files=all']);
	if (status === null) return null;
	const candidates = status.split('\n').filter(Boolean).map((l) => l.slice(3).replace(/^"|"$/g, '').split(' -> ').pop());
	const named = (command.match(/git\s+add\s+(.+)/) || [, ''])[1].split(/\s+/).filter((a) => a && !a.startsWith('-'));
	const broad = /git\s+add\s+(-A|--all|\.|\*|-u)(\s|$)/.test(command) || /git\s+commit\b.*\s-(a\w*|-all)\b/.test(command);
	const staged = candidates.filter((f) => broad || named.some((n) => f === n || f.startsWith(n.replace(/\/$/, '') + '/') || n === '.'));
	const risky = staged.filter((f) => secretFileVerdict(f, config) === 'deny');
	if (risky.length) {
		return `This would stage ${risky.join(', ')}, which holds secrets and is not in .gitignore. Add it to .gitignore first, then stage the other files.`;
	}
	// The commit check reads what is already staged, so "git add x && git commit" would slip past it.
	// Read the files about to be staged instead.
	const hits = [];
	for (const f of staged) {
		let text;
		try {
			const full = path.join(cwd, f);
			if (fs.statSync(full).size > 1024 * 1024) continue;
			text = fs.readFileSync(full, 'utf8');
		} catch {
			continue;
		}
		if (text.includes('\u0000')) continue; // binary
		for (const s of findSecrets(text)) hits.push(`${f}:${text.slice(0, s.index).split('\n').length} ${s.name} ${mask(s.value)}`);
	}
	if (hits.length) {
		return `This would stage files that contain secrets:\n- ${hits.slice(0, 10).join('\n- ')}\nMove the values to .env and read them from the environment, then stage again.`;
	}
	return null;
}

function secretsInDiff(diff) {
	const hits = [];
	let file = '';
	let line = 0;
	for (const l of diff.split('\n')) {
		if (l.startsWith('+++ ')) file = l.replace(/^\+\+\+ (b\/)?/, '');
		else if (l.startsWith('@@')) line = Number((l.match(/\+(\d+)/) || [, 0])[1]) - 1;
		else if (l.startsWith('+')) {
			line++;
			for (const s of findSecrets(l.slice(1))) hits.push(`${file}:${line} ${s.name} ${mask(s.value)}`);
		} else if (!l.startsWith('-')) line++;
		if (secretFileVerdict(file) === 'deny' && !hits.some((h) => h.startsWith(file + ' '))) hits.push(`${file} (secret file)`);
	}
	return [...new Set(hits)];
}

function checkStaged(cwd) {
	const diff = git(cwd, ['diff', '--cached', '--unified=0', '--no-color']);
	if (!diff) return null;
	const hits = secretsInDiff(diff);
	return hits.length ? `The staged changes contain secrets:\n- ${hits.slice(0, 10).join('\n- ')}\nUnstage them (git restore --staged <file>), move the values to .env, and commit again.` : null;
}

function checkUnpushed(cwd) {
	const range = git(cwd, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}']) ? '@{u}..HEAD' : 'HEAD';
	const log = git(cwd, ['log', '-p', '--no-color', '--unified=0', range]);
	if (!log) return null;
	const hits = secretsInDiff(log);
	return hits.length ? `The commits about to be pushed contain secrets:\n- ${hits.slice(0, 10).join('\n- ')}\nA pushed key must be treated as leaked. Remove it from history before pushing, and rotate it if it was ever pushed before.` : null;
}

// ---------------------------------------------------------------- the hook

function loadConfig(projectDir) {
	try {
		return JSON.parse(fs.readFileSync(path.join(projectDir, '.claude', 'keyguard.json'), 'utf8'));
	} catch {
		return {};
	}
}

function log(projectDir, entry) {
	try {
		fs.appendFileSync(path.join(projectDir, '.claude', 'keyguard.log'), `${new Date().toISOString()} ${entry}\n`);
	} catch {}
}

function deepRedact(value, counter) {
	if (typeof value === 'string') {
		const r = redact(value);
		if (r !== value) counter.n++;
		return r;
	}
	if (Array.isArray(value)) return value.map((v) => deepRedact(v, counter));
	if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, deepRedact(v, counter)]));
	return value;
}

export function decide(input, config = {}) {
	const event = input.hook_event_name;
	const tool = input.tool_name;
	const ti = input.tool_input || {};
	const cwd = input.cwd || process.cwd();

	if (event === 'UserPromptSubmit') {
		const keys = findSecrets(input.prompt || '');
		if (!keys.length) return null;
		return {
			output: { decision: 'block', reason: `Your message was not sent: it contains ${a(keys[0].name)} (${mask(keys[0].value)}). Put the key in .env yourself and tell Claude the variable name instead.` },
			log: `blocked prompt containing ${keys[0].name} ${mask(keys[0].value)}`,
		};
	}

	if (event === 'PreToolUse') {
		const deny = (reason) => ({ output: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `keyguard: ${reason}` } }, log: `denied ${tool}: ${reason.split('\n')[0]}` });
		const ask = (reason) => ({ output: { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: `keyguard: ${reason}` } }, log: `asked ${tool}: ${reason}` });

		const file = ti.file_path || ti.notebook_path || ti.path;
		const verdict = ['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'NotebookRead'].includes(tool) ? secretFileVerdict(file, config) : null;
		if (verdict === 'deny') {
			if (tool === 'Read' || tool === 'NotebookRead') return deny(`${path.basename(file)} holds secrets and is off limits. Ask the user which variable names it defines, and reference them from the environment in code.`);
			return ask(`${path.basename(file)} holds secrets. Approve only if you want Claude to change it.`);
		}
		if (verdict === 'ask') return ask(`${path.basename(file)} contains passwords as well as code. Approve only if Claude needs it for this task.`);

		if (tool === 'Grep' && secretFileVerdict(ti.path, config) === 'deny') return deny(`Searching inside ${path.basename(ti.path)} would expose secrets.`);

		const written = [ti.content, ti.new_string, ti.new_source, ...(ti.edits || []).map((e) => e.new_string)].filter((v) => typeof v === 'string').join('\n');
		const keys = findSecrets(written);
		if (keys.length) {
			return deny(`This would write ${a(keys[0].name)} (${mask(keys[0].value)}) into ${file ? path.basename(file) : 'a file'}. Keys belong in .env. Read it from the environment in code instead (process.env.NAME, getenv('NAME')).`);
		}

		if (tool === 'Bash' && ti.command) {
			const reason = checkCommand(ti.command, cwd, config);
			if (reason) return deny(reason);
		}
		return null;
	}

	if (event === 'PostToolUse') {
		const counter = { n: 0 };
		const cleaned = deepRedact(input.tool_response, counter);
		if (!counter.n) return null;
		return {
			output: { hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: cleaned, additionalContext: 'keyguard redacted one or more secrets from this tool output. The values are not available; do not try to recover them.' } },
			log: `redacted ${counter.n} value(s) from ${tool} output`,
		};
	}
	return null;
}

// Run as a hook when executed directly, not when imported by the tests.
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('keyguard.mjs')) {
	let raw = '';
	process.stdin.on('data', (c) => (raw += c));
	process.stdin.on('end', () => {
		let input;
		try {
			input = JSON.parse(raw);
		} catch {
			process.exit(0); // Never break Claude Code over a malformed payload.
		}
		const projectDir = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
		const result = decide(input, loadConfig(projectDir));
		if (result) {
			log(projectDir, result.log);
			process.stdout.write(JSON.stringify(result.output));
		}
		process.exit(0);
	});
}
