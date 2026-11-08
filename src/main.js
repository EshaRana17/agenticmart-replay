import { buildIncident, buildReport, readLog, renderIncident, renderReport } from './replay.js';

const USAGE = `usage:
  agenticmart-replay report <guard.jsonl> [--json]
  agenticmart-replay incident <guard.jsonl> --id <n> [--json]
`;

export function main(argv) {
  try {
    const [cmd, ...rest] = argv;
    if (!cmd || cmd === '--help' || cmd === '-h') {
      process.stdout.write(USAGE);
      return;
    }
    let json = false;
    let id;
    const positional = [];
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === '--json') json = true;
      else if (rest[i] === '--id') id = rest[(i += 1)];
      else if (rest[i].startsWith('--')) throw new Error(`unknown option ${rest[i]}\n${USAGE}`);
      else positional.push(rest[i]);
    }
    const file = positional[0];
    if (!file || (cmd !== 'report' && cmd !== 'incident')) throw new Error(USAGE);
    const log = readLog(file);
    let data;
    let text;
    if (cmd === 'report') {
      data = buildReport(log, file);
      text = renderReport(data);
    } else {
      if (!/^[1-9]\d*$/.test(id ?? '')) throw new Error('incident needs --id <n>, a positive entry number from the report');
      data = buildIncident(log, Number(id));
      text = renderIncident(data);
    }
    process.stdout.write(json ? `${JSON.stringify(data, null, 2)}\n` : text);
  } catch (e) {
    process.stderr.write(`agenticmart-replay: ${e.message}\n`);
    process.exitCode = 2;
  }
}
