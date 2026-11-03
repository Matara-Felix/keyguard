// node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { decide, findSecrets, redact, secretFileVerdict } from '../.claude/hooks/keyguard.mjs';

import { FAKE } from './fixtures.mjs';

const pre = (tool, tool_input, cwd = '/tmp') => decide({ hook_event_name: 'PreToolUse', tool_name: tool, tool_input, cwd });
const decision = (r) => r?.output?.hookSpecificOutput?.permissionDecision ?? null;

// ---------------------------------------------------------------- detection

test('finds every key format', () => {
	for (const [name, key] of Object.entries(FAKE)) {
		assert.equal(findSecrets(`x = "${key}"`).length, 1, name);
	}
});

test('names the provider correctly', () => {
	assert.equal(findSecrets(FAKE.openrouter)[0].name, 'OpenRouter API key');
	assert.equal(findSecrets(FAKE.anthropic)[0].name, 'Anthropic API key');
	assert.equal(findSecrets(FAKE.openai)[0].name, 'OpenAI API key');
});

test('finds a high-entropy value assigned to a key-like name', () => {
	assert.equal(findSecrets(`const API_KEY = "9fK2xQ7mZp4LwR8tVb3N";`).length, 1);
	assert.equal(findSecrets(`DB_PASSWORD='h7#Kq92!xLm4Pz0w'`).length, 1);
});

test('ignores placeholders and env lookups', () => {
	for (const s of [
		`API_KEY="your-api-key-here"`,
		`OPENROUTER_API_KEY=sk-or-v1-xxxxxxxx`,
		`const key = process.env.OPENROUTER_API_KEY;`,
		`$key = getenv('OPENROUTER_API_KEY');`,
		`password: "changeme-changeme"`,
		`token = "${'a'.repeat(30)}"`,
	]) {
		assert.deepEqual(findSecrets(s), [], s);
	}
});

test('finds a private key block', () => {
	assert.equal(findSecrets('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----')[0].name, 'private key');
});

test('redaction keeps the last four characters and nothing usable', () => {
	const r = redact(`KEY=${FAKE.openrouter}`);
	assert.ok(!r.includes(FAKE.openrouter));
	assert.match(r, /\[REDACTED OpenRouter API key sk-or-v1-…[0-9a-f]{4}\]/);
});

// ---------------------------------------------------------------- secret files

test('classifies secret files', () => {
	for (const f of ['.env', '/app/.env', '.env.local', '.env.production', 'C:\\proj\\.env', 'server.pem', 'id_rsa', '/home/u/.ssh/config', '/home/u/.aws/credentials', 'credentials.json', '.npmrc', 'secrets.yaml']) {
		assert.equal(secretFileVerdict(f), 'deny', f);
	}
	for (const f of ['.env.example', '.env.sample', 'env.js', 'environment.ts', 'id_rsa.pub', 'README.md', 'src/.envrc.md']) {
		assert.equal(secretFileVerdict(f), null, f);
	}
	assert.equal(secretFileVerdict('/var/www/html/wp-config.php'), 'ask');
});

test('Read of .env is denied, .env.example is allowed', () => {
	assert.equal(decision(pre('Read', { file_path: '/p/.env' })), 'deny');
	assert.equal(decision(pre('Read', { file_path: '/p/.env.example' })), null);
});

test('wp-config.php asks the user instead of denying', () => {
	assert.equal(decision(pre('Read', { file_path: '/var/www/wp-config.php' })), 'ask');
});

test('editing .env asks the user', () => {
	assert.equal(decision(pre('Edit', { file_path: '/p/.env', old_string: 'A=1', new_string: 'A=2' })), 'ask');
});

test('Grep inside .env is denied', () => {
	assert.equal(decision(pre('Grep', { pattern: 'KEY', path: '/p/.env' })), 'deny');
});

// ---------------------------------------------------------------- writing keys into code

test('writing a real key into code is denied, with the fix in the reason', () => {
	const r = pre('Write', { file_path: '/p/src/client.js', content: `const key = "${FAKE.openrouter}";` });
	assert.equal(decision(r), 'deny');
	assert.match(r.output.hookSpecificOutput.permissionDecisionReason, /process\.env/);
	assert.ok(!r.output.hookSpecificOutput.permissionDecisionReason.includes(FAKE.openrouter), 'the reason never repeats the key');
});

test('an Edit that adds a key is denied', () => {
	assert.equal(decision(pre('Edit', { file_path: '/p/config.php', old_string: "'key' => ''", new_string: `'key' => '${FAKE.stripe}'` })), 'deny');
});

test('writing code that reads the environment is allowed', () => {
	assert.equal(decision(pre('Write', { file_path: '/p/src/client.js', content: 'const key = process.env.OPENROUTER_API_KEY;' })), null);
});

// ---------------------------------------------------------------- shell

const bash = (command, cwd) => decision(pre('Bash', { command }, cwd));

test('shell commands that print a secret file are denied', () => {
	for (const c of [
		'cat .env',
		'head -5 .env.local',
		'grep KEY .env',
		'less config/.env',
		'source .env && node app.js',
		`python3 -c "print(open('.env').read())"`,
		`node -e "console.log(require('fs').readFileSync('.env','utf8'))"`,
		'base64 .env',
		'cp .env /tmp/backup',
		'cat ~/.aws/credentials',
		'cat ~/.ssh/id_ed25519',
	]) {
		assert.equal(bash(c), 'deny', c);
	}
});

test('harmless commands that mention .env are allowed', () => {
	for (const c of ['ls -la', 'ls -a .env', 'test -f .env && echo present', 'cp .env.example .env', 'git check-ignore .env', 'npm test', 'cat .env.example']) {
		assert.equal(bash(c), null, c);
	}
});

test('dumping or echoing secret environment variables is denied', () => {
	for (const c of ['env', 'printenv', 'export -p', 'env | grep KEY', 'echo $OPENROUTER_API_KEY', 'printf "%s" "${ANTHROPIC_API_KEY}"', 'printenv GITHUB_TOKEN']) {
		assert.equal(bash(c), 'deny', c);
	}
	assert.equal(bash('echo $HOME'), null);
	assert.equal(bash('printenv PATH'), null);
});

test('a key typed into a command is denied', () => {
	assert.equal(bash(`curl -H "Authorization: Bearer ${FAKE.openrouter}" https://openrouter.ai/api/v1/models`), 'deny');
	assert.equal(bash('curl -H "Authorization: Bearer $OPENROUTER_API_KEY" https://openrouter.ai/api/v1/models'), null);
});

// ---------------------------------------------------------------- git

function repo() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyguard-'));
	const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
	g('init', '-q');
	g('config', 'user.email', 't@t');
	g('config', 'user.name', 't');
	fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(1)\n');
	g('add', 'app.js');
	g('commit', '-qm', 'init');
	return { dir, g };
}

test('git add . is denied when .env is not ignored, allowed once it is', () => {
	const { dir } = repo();
	fs.writeFileSync(path.join(dir, '.env'), `OPENROUTER_API_KEY=${FAKE.openrouter}\n`);
	assert.equal(bash('git add .', dir), 'deny');
	assert.equal(bash('git add -A && git commit -m wip', dir), 'deny');
	assert.equal(bash('git add .env', dir), 'deny');
	assert.equal(bash('git add app.js', dir), null);
	fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
	assert.equal(bash('git add .', dir), null);
});

test('git commit is denied when a staged file contains a key', () => {
	const { dir, g } = repo();
	fs.writeFileSync(path.join(dir, 'config.js'), `module.exports = { key: "${FAKE.anthropic}" };\n`);
	g('add', 'config.js');
	const r = pre('Bash', { command: 'git commit -m "add config"' }, dir);
	assert.equal(decision(r), 'deny');
	assert.match(r.output.hookSpecificOutput.permissionDecisionReason, /config\.js:1 Anthropic API key/);
});

test('git push is denied when an unpushed commit contains a key, even one made outside Claude', () => {
	const { dir, g } = repo();
	fs.writeFileSync(path.join(dir, 'deploy.sh'), `export AWS_ACCESS_KEY_ID=${FAKE.aws}\n`);
	g('add', 'deploy.sh');
	g('commit', '-qm', 'deploy script');
	assert.equal(bash('git push origin main', dir), 'deny');
});

test('a clean commit and push are allowed', () => {
	const { dir, g } = repo();
	fs.writeFileSync(path.join(dir, 'app.js'), 'console.log(process.env.OPENROUTER_API_KEY ? "set" : "missing")\n');
	g('add', 'app.js');
	assert.equal(bash('git commit -m "read key from env"', dir), null);
	assert.equal(bash('git push', dir), null);
});

// ---------------------------------------------------------------- prompts and outputs

test('a prompt containing a key is blocked before it is sent', () => {
	const r = decide({ hook_event_name: 'UserPromptSubmit', prompt: `use this key: ${FAKE.openrouter} for the client` });
	assert.equal(r.output.decision, 'block');
	assert.ok(!r.output.reason.includes(FAKE.openrouter));
	assert.equal(decide({ hook_event_name: 'UserPromptSubmit', prompt: 'read the key from OPENROUTER_API_KEY' }), null);
});

test('tool output is redacted wherever the key sits in the response', () => {
	const r = decide({
		hook_event_name: 'PostToolUse',
		tool_name: 'Bash',
		tool_response: { stdout: `./legacy/config.js:3:  key: "${FAKE.openrouter}",\n./app.js:1:ok`, stderr: '', interrupted: false },
	});
	const out = r.output.hookSpecificOutput.updatedToolOutput;
	assert.ok(!JSON.stringify(out).includes(FAKE.openrouter));
	assert.match(out.stdout, /\.\/app\.js:1:ok/, 'everything else is kept');
	assert.equal(out.interrupted, false, 'the shape of the response is kept');
});

test('clean output passes through untouched', () => {
	assert.equal(decide({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_response: { stdout: 'all tests passed' } }), null);
});

// ---------------------------------------------------------------- found by the live runs

test('grep output from .env is redacted even when the value does not look random', () => {
	const r = decide({ hook_event_name: 'PostToolUse', tool_name: 'Grep', tool_response: { content: './.env:2:DB_PASSWORD=sunshine2024\n./README.md:3:Set OPENROUTER_API_KEY in .env.' } });
	const out = JSON.stringify(r.output.hookSpecificOutput.updatedToolOutput);
	assert.ok(!out.includes('sunshine2024'));
	assert.ok(out.includes('README.md:3:Set OPENROUTER_API_KEY in .env.'), 'a line that only names the variable is kept');
});

test('env-style lines keep config that is not secret', () => {
	assert.deepEqual(findSecrets('PORT=3000\nNODE_ENV=production\nTOKEN_TTL=3600\nAPI_KEY=$OPENROUTER_API_KEY'), []);
});

test('git add of a file containing a key is denied, even in one command with the commit', () => {
	const { dir } = repo();
	fs.mkdirSync(path.join(dir, 'legacy'));
	fs.writeFileSync(path.join(dir, 'legacy', 'config.js'), `module.exports = {\n  anthropicKey: "${FAKE.anthropic}",\n};\n`);
	const r = pre('Bash', { command: 'git add legacy/ app.js && git commit -m "initial commit"' }, dir);
	assert.equal(decision(r), 'deny');
	assert.match(r.output.hookSpecificOutput.permissionDecisionReason, /legacy\/config\.js:2 Anthropic API key/);
});

test('messages use the right article', () => {
	const r = decide({ hook_event_name: 'UserPromptSubmit', prompt: `key ${FAKE.openrouter}` });
	assert.match(r.output.reason, /contains an OpenRouter API key/);
});

test('wildcards that could expand to .env are denied', () => {
	for (const c of ['cat .e*', 'base64 .en?', 'cat .??v', 'grep KEY *env*', 'head .*']) assert.equal(bash(c), 'deny', c);
	for (const c of ['ls .*', 'rm -rf dist/*', 'cat src/*.js', 'node scripts/*.mjs']) assert.equal(bash(c), null, c);
});
