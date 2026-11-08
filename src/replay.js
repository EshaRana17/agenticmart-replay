import fs from 'node:fs';

const CONTEXT = 5;

const RULES = {
  denyTools: {
    meaning: 'This tool is named on the policy deny list.',
    next: ['Confirm the deny entry is still what you want.', 'Ask why the agent tried this tool: read the prompt or task that came just before it.', 'If the tool was hidden from tools/list, check whether the client cached an older list.'],
  },
  allowTools: {
    meaning: 'This tool is not on the policy allow list.',
    next: ['Decide whether the tool should be added to allowTools.', 'Compare the tool name against a baseline of the server to see whether it is new.'],
  },
  denyArgPatterns: {
    meaning: 'The call arguments matched a regular expression the policy denies.',
    next: ['Read the arguments above and work out where that value came from.', 'Check earlier tool results for text that may have steered the agent toward this value.', 'If it is a false positive, narrow the pattern or scope it to one tool.'],
  },
  maxCallsPerMinute: {
    meaning: 'Too many calls went through within one minute.',
    next: ['Look at the calls just before this one for a runaway pattern.', 'Raise the limit only if this rate is normal for the task.'],
  },
  maxIdenticalCalls: {
    meaning: 'The same tool was called with the same arguments more times than the policy permits. This is the loop breaker.',
    next: ['Look at what the tool returned on earlier attempts, since agents often repeat a call that keeps failing.', 'Restart the agent run after fixing the cause; the count lasts as long as the guard process.'],
  },
  maxTotalCalls: {
    meaning: 'The total call budget for this guard process was used up.',
    next: ['Check whether the run was productive or stuck.', 'Restart the guard to reset the budget, or raise the limit.'],
  },
  toolChanged: {
    meaning: 'A tool description no longer matches the hash recorded in expectedTools.',
    next: ['Compare a fresh baseline against the approved one with agenticmart-baseline diff.', 'Read the new description for instructions aimed at the model.', 'Check whether the server package or version changed since approval.'],
  },
  unexpectedTool: {
    meaning: 'A tool appeared that is not in expectedTools.',
    next: ['Find out whether the server was updated.', 'Read the new tool description before approving it.', 'Regenerate the baseline and policy if the tool is legitimate.'],
  },
  invalidRequest: {
    meaning: 'The request was malformed, so the guard did not forward it.',
    next: ['Check the client or agent that sent it for a bug.'],
  },
  parseError: {
    meaning: 'A line on the stream was not valid JSON-RPC, so the guard did not forward it.',
    next: ['Check the client for a framing bug.', 'Look for something else writing to the same stream.'],
  },
  batch: {
    meaning: 'The client sent a JSON-RPC batch, which this guard does not forward.',
    next: ['Check whether the client can send single requests.'],
  },
  internalError: {
    meaning: 'The guard could not evaluate this call and refused it.',
    next: ['Check the guard stderr output and report the case if it repeats.'],
  },
};
const UNKNOWN_RULE = { meaning: 'This log names a rule this version of replay does not recognize.', next: ['Read the reason text and the guard version that wrote the log.'] };

export function readLog(file) {
  const entries = [];
  let skipped = 0;
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    let e;
    try { e = JSON.parse(line); } catch { skipped += 1; return; }
    if (e === null || typeof e !== 'object' || Array.isArray(e) || typeof e.decision !== 'string') { skipped += 1; return; }
    entries.push({ n: i + 1, ...e });
  });
  return { entries, skipped };
}

function tally(list, key) {
  const out = {};
  for (const e of list) {
    const k = key(e) ?? 'unknown';
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

export function buildReport({ entries, skipped }, source) {
  const calls = entries.filter((e) => e.event === 'tools/call');
  const blocked = calls.filter((e) => e.decision === 'block');
  const listBlocks = entries.filter((e) => e.event === 'tools/list' && e.decision === 'block');
  const protocol = entries.filter((e) => e.event === 'protocol' && e.decision === 'block');
  return {
    source,
    firstTimestamp: entries[0]?.timestamp ?? null,
    lastTimestamp: entries.at(-1)?.timestamp ?? null,
    summary: {
      entries: entries.length,
      unreadableLines: skipped,
      toolCalls: calls.length,
      allowed: calls.filter((e) => e.decision === 'allow').length,
      blocked: blocked.length,
      toolsHiddenFromLists: listBlocks.length,
      changesLogged: entries.filter((e) => e.decision === 'log' && (e.rule === 'toolChanged' || e.rule === 'unexpectedTool')).length,
      protocolRejections: protocol.length,
      blockedByRule: tally(blocked, (e) => e.rule),
      blockedByTool: tally(blocked, (e) => e.tool),
    },
    timeline: entries.map(({ n, timestamp, event, tool, decision, rule, reason }) => ({ n, timestamp, event, tool: tool ?? null, decision, rule: rule ?? null, reason: reason ?? '' })),
  };
}

export function buildIncident({ entries }, n) {
  const at = entries.findIndex((e) => e.n === n);
  if (at === -1) throw new Error(`no log entry with number ${n}`);
  const entry = entries[at];
  if (entry.decision !== 'block') throw new Error(`entry ${n} has decision "${entry.decision}", not "block"`);
  const rule = Object.hasOwn(RULES, entry.rule ?? '') ? RULES[entry.rule] : UNKNOWN_RULE;
  return {
    entry,
    before: entries.slice(Math.max(0, at - CONTEXT), at),
    rule: entry.rule ?? null,
    meaning: rule.meaning,
    checkNext: rule.next,
  };
}

// Log fields can hold server-chosen text, so nothing from them may act as Markdown.
function code(value) {
  const text = String(value ?? 'none').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/`/g, "'");
  return `\`${text.slice(0, 200)}\``;
}

function plain(value) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/([\\`*_[\]<>|#~])/g, '\\$1').slice(0, 500);
}

function describe(e) {
  const who = e.tool ? `tool ${code(e.tool)}` : 'no tool';
  if (e.event === 'tools/call') return `${e.decision === 'allow' ? 'Allowed' : 'Blocked'} a call to ${who}. ${plain(e.reason)}`;
  if (e.event === 'tools/list') return e.tool ? `${e.decision === 'block' ? 'Hid' : 'Noted'} ${who} in a tool list. ${plain(String(e.reason ?? '').replace('hidden from tools/list: ', ''))}` : `Tool list: ${plain(e.reason)}`;
  return `${plain(e.event)}: ${plain(e.reason)}`;
}

function lineFor(e) {
  return `- **#${e.n}** ${code(e.timestamp)} ${describe(e)}`;
}

function counts(obj) {
  const rows = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  return rows.length ? rows.map(([k, v]) => `  - ${code(k)}: ${v}`).join('\n') : '  - none';
}

const SCOPE = 'This report covers only what passed through agenticmart-guard and was written to this log. It cannot show what a server did internally, and the log is a plain file that is not protected against editing.';

export function renderReport(r) {
  const s = r.summary;
  const parts = [
    '# Guard log report', '',
    `Source: ${code(r.source)}`,
    `Period: ${code(r.firstTimestamp)} to ${code(r.lastTimestamp)}`, '',
    '## Summary', '',
    `- Tool calls seen: ${s.toolCalls} (${s.allowed} allowed, ${s.blocked} blocked)`,
    `- Tools hidden from lists: ${s.toolsHiddenFromLists}`,
    `- Tool changes logged but not blocked: ${s.changesLogged}`,
    `- Protocol messages rejected: ${s.protocolRejections}`,
  ];
  if (s.unreadableLines) parts.push(`- Unreadable log lines skipped: ${s.unreadableLines}`);
  parts.push('- Blocked calls by rule:', counts(s.blockedByRule), '- Blocked calls by tool:', counts(s.blockedByTool), '', '## Timeline', '');
  parts.push(r.timeline.length ? r.timeline.map(lineFor).join('\n') : 'The log has no readable entries.');
  parts.push('', `Use \`agenticmart-replay incident <log> --id <n>\` with a blocked entry number for detail.`, '', '## Scope', '', SCOPE, '');
  return parts.join('\n');
}

function fence(text) {
  let ticks = '```';
  while (text.includes(ticks)) ticks += '`';
  return `${ticks}json\n${text}\n${ticks}`;
}

export function renderIncident(inc) {
  const e = inc.entry;
  const args = JSON.stringify(e.arguments ?? null, null, 2) ?? 'null';
  const parts = [
    `# Incident: entry #${e.n}`, '',
    '## What happened', '',
    `${describe(e)}`,
    `Time: ${code(e.timestamp)}`, '',
    '## Arguments as logged (secret-looking keys are redacted)', '',
    fence(args.length > 2000 ? `${args.slice(0, 2000)}\n... truncated` : args), '',
    '## Rule that fired', '',
    `${code(inc.rule)}: ${inc.meaning}`, '',
    '## Just before', '',
    inc.before.length ? inc.before.map(lineFor).join('\n') : 'This was the first entry in the log.', '',
    '## What to check next', '',
    inc.checkNext.map((t) => `- ${t}`).join('\n'), '',
    '## Scope', '', SCOPE, '',
  ];
  return parts.join('\n');
}
