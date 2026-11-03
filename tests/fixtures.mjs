// Fake keys in the real formats. None of these work anywhere.
const rnd = (chars, n) => Array.from({ length: n }, (_, i) => chars[(i * 7 + 3) % chars.length]).join('');
const HEX = '0123456789abcdef';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const FAKE = {
	openrouter: 'sk-or-v1-' + rnd(HEX, 64),
	anthropic: 'sk-ant-api03-' + rnd(ALNUM + '_-', 80),
	openai: 'sk-proj-' + rnd(ALNUM, 48),
	aws: 'AKIA' + rnd('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16),
	github: 'ghp_' + rnd(ALNUM, 36),
	stripe: 'sk_live_' + rnd(ALNUM, 24),
};

