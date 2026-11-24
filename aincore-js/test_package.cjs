const { execFileSync } = require('node:child_process');
const assert = require('node:assert/strict');

const modules = ['address', 'bcs', 'connection', 'da', 'index', 'keypair', 'stateProof', 'transaction'];
const expected = ['package.json', ...modules.flatMap(name => [`dist/${name}.js`, `dist/${name}.d.ts`])];
const [pack] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: __dirname,
    encoding: 'utf8',
}));
assert.deepEqual(pack.files.map(file => file.path).sort(), expected.sort());
console.log('Verified all 17 distributable files.');
