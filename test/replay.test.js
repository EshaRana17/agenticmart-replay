import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(here, '..', 'bin', 'agenticmart-replay.js');

function run(...args) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

const row = (o) => JSON.stringify({ timestamp: '2026-11-08T10:00:00.000Z', event: 'tools/call', tool: 'read_file', arguments: {}, decision: 'allow', reason: 'passed all policy rules', rule: null, requestId: 1, ...o });

function logFile(lines) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'replay-test-')), 'guard.jsonl');
  fs.writeFileSync(f, `${lines.join('\n')}\n`);
  return f;
}

const sample = () => logFile([
  row({ event: 'lifecycle', tool: null, arguments: null, decision: 'log', rule: 'start', reason: 'started server command node' }),
  row({ event: 'tools/list', tool: 'delete_all', arguments: null, decision: 'block', rule: 'denyTools', reason: 'hidden from tools/list: tool "delete_all" is on the deny list' }),
  row({ arguments: { path: 'a' } }),
  row({ arguments: { path: 'a' } }),
  row({ arguments: { path: 'a' }, decision: 'block', rule: 'maxIdenticalCalls', reason: 'same tool and arguments already called 2 times, limit is 2' }),
  row({ tool: 'write_file', arguments: { cmd: 'rm -rf /', token: '[REDACTED]' }, decision: 'block', rule: 'denyArgPatterns', reason: 'arguments match denied pattern rm -rf' }),
]);

test('report summarizes calls and rules in Markdown', () => {
  const r = run('report', sample());
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^# Guard log report/);
  assert.match(r.stdout, /Tool calls seen: 4 \(2 allowed, 2 blocked\)/);
  assert.match(r.stdout, /Tools hidden from lists: 1/);
  assert.match(r.stdout, /`maxIdenticalCalls`: 1/);
  assert.match(r.stdout, /\*\*#5\*\*/);
  assert.match(r.stdout, /only what passed through agenticmart-guard/);
});

test('report --json is parseable and matches', () => {
  const r = run('report', sample(), '--json');
  const d = JSON.parse(r.stdout);
  assert.equal(d.summary.blocked, 2);
  assert.equal(d.timeline.length, 6);
  assert.deepEqual(d.summary.blockedByRule, { maxIdenticalCalls: 1, denyArgPatterns: 1 });
});

test('incident explains the rule, context and next steps', () => {
  const r = run('incident', sample(), '--id', '5');
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /# Incident: entry #5/);
  assert.match(r.stdout, /loop breaker/);
  assert.match(r.stdout, /## Just before[\s\S]*#4/);
  assert.match(r.stdout, /## What to check next/);
});

test('incident --json returns the structured incident', () => {
  const d = JSON.parse(run('incident', sample(), '--id', '6', '--json').stdout);
  assert.equal(d.rule, 'denyArgPatterns');
  assert.equal(d.entry.tool, 'write_file');
  assert.equal(d.before.length, 5);
  assert.ok(d.checkNext.length > 0);
});

test('incident refuses an entry that was not blocked', () => {
  const r = run('incident', sample(), '--id', '3');
  assert.equal(r.code, 2);
  assert.match(r.stderr, /not "block"/);
});

test('incident refuses a missing or invalid id', () => {
  assert.equal(run('incident', sample(), '--id', '99').code, 2);
  assert.equal(run('incident', sample()).code, 2);
  assert.equal(run('incident', sample(), '--id', 'abc').code, 2);
});

test('unreadable lines are counted, and numbering still matches file lines', () => {
  const f = logFile([row({}), '{torn line', row({ decision: 'block', rule: 'denyTools', reason: 'x' })]);
  const d = JSON.parse(run('report', f, '--json').stdout);
  assert.equal(d.summary.unreadableLines, 1);
  assert.equal(run('incident', f, '--id', '3').code, 0);
});

test('an empty log still produces a report', () => {
  const f = logFile([]);
  const r = run('report', f);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /no readable entries/);
});

test('a missing file is an error', () => {
  assert.equal(run('report', path.join(os.tmpdir(), 'nope-agenticmart.jsonl')).code, 2);
});

test('server-chosen tool names cannot inject Markdown', () => {
  const f = logFile([row({ tool: 'x`](http://evil)\n# Heading', decision: 'block', rule: 'denyTools', reason: '[click](http://evil) <img>' })]);
  const r = run('report', f);
  assert.equal(r.stdout.includes('\n# Heading'), false);
  assert.equal(r.stdout.includes('[click]('), false);
  assert.equal(r.stdout.includes('<img>'), false);
});

test('arguments containing a code fence stay inside the fence', () => {
  const f = logFile([row({ arguments: { a: '```\n# out' }, decision: 'block', rule: 'denyTools', reason: 'x' })]);
  const r = run('incident', f, '--id', '1');
  assert.match(r.stdout, /````json/);
});

test('an unknown rule is handled', () => {
  const f = logFile([row({ decision: 'block', rule: 'futureRule', reason: 'x' })]);
  assert.match(run('incident', f, '--id', '1').stdout, /does not recognize/);
});
