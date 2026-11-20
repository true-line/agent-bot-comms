// Build the installed HQ plugin in an existing staging directory, without network access.
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import plugin from '../lib/hq-plugin/plugin.mjs';
import { staticManifest } from '../lib/vendor/agent-bot-sdk/plugin.mjs';

if (process.argv.length !== 3) throw new Error('usage: node scripts/build-hq-plugin.mjs <existing staging directory>');
const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(process.argv[2]);
const destination = join(output, 'agent-comms');
if (lstatSync(destination, { throwIfNoEntry: false })) throw new Error('the agent-comms destination already exists');

// Only the private staging directory is visible until the complete tree is published.
process.umask(0o022);
const work = mkdtempSync(join(output, '.hq-plugin-'));
try {
  const tree = join(work, 'agent-comms');
  mkdirSync(tree);
  const sdk = 'lib/vendor/agent-bot-sdk';
  const source = JSON.parse(readFileSync(join(root, sdk, 'source.json'), 'utf8'));
  function copySource(path, digest) {
    const input = join(root, path);
    const target = join(tree, path);
    if (!lstatSync(input).isFile()) throw new Error(`expected a regular source file: ${path}`);
    const bytes = readFileSync(input);
    if (digest !== undefined && createHash('sha256').update(bytes).digest('hex') !== digest) {
      throw new Error(`vendored SDK digest mismatch: ${path}`);
    }
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
  for (const path of ['LICENSE', 'lib/hq-plugin/broker.mjs', 'lib/hq-plugin/notices.mjs', 'lib/hq-plugin/plugin.mjs',
    `${sdk}/source.json`, `${sdk}/LICENSE`]) {
    copySource(path);
  }
  for (const [path, digest] of Object.entries(source.files)) {
    if (!/^sdk\/(?:[\w-]+\/)*[\w-]+(?:\.[\w-]+)*$/.test(path)) throw new Error('invalid vendored SDK source path');
    copySource(join(sdk, path.slice('sdk/'.length)), digest);
  }
  // Broker code reads the package identity relative to its original source location.
  const { name, version } = plugin;
  writeFileSync(join(tree, 'package.json'), JSON.stringify({ name, version }, null, 2) + '\n');
  writeFileSync(join(tree, 'plugin.json'), JSON.stringify(staticManifest(plugin), null, 2) + '\n');
  writeFileSync(join(tree, 'plugin.mjs'), "export { default } from './lib/hq-plugin/plugin.mjs';\n");
  renameSync(tree, destination);
} finally {
  rmSync(work, { recursive: true, force: true });
}
