# agenticmart-replay

agenticmart-replay reads an [agenticmart-guard](https://github.com/EshaRana17/agenticmart-guard) JSONL log and writes a plain-English incident report in Markdown.

It has no runtime dependencies and needs Node 20 or newer.

## Install

```sh
npx github:EshaRana17/agenticmart-replay report guard.jsonl
```

## Usage

```sh
agenticmart-replay report <guard.jsonl> [--json]
agenticmart-replay incident <guard.jsonl> --id <n> [--json]
```

Entry numbers are line numbers in the log and are shown in the report timeline. `incident` works on blocked entries.

Real output from a test run, trimmed where marked:

```text
$ agenticmart-replay report guard.jsonl
# Guard log report

## Summary

- Tool calls seen: 5 (2 allowed, 3 blocked)
- Tools hidden from lists: 1
- Tool changes logged but not blocked: 0
- Protocol messages rejected: 0
- Blocked calls by rule:
  - `maxIdenticalCalls`: 1
  - `denyArgPatterns`: 1
  - `denyTools`: 1

[trimmed]

$ agenticmart-replay incident guard.jsonl --id 7
# Incident: entry #7

## What happened

Blocked a call to tool `read_file`. arguments match denied pattern \\.ssh
Time: `2026-11-08T11:25:41.132Z`

## Arguments as logged (secret-looking keys are redacted)

{
  "path": "/home/me/.ssh/id_rsa",
  "api_key": "[REDACTED]"
}

## Rule that fired

`denyArgPatterns`: The call arguments matched a regular expression the policy denies.

## Just before

- **#5** `2026-11-08T11:25:40.874Z` Allowed a call to tool `read_file`. passed all policy rules
- **#6** `2026-11-08T11:25:41.005Z` Blocked a call to tool `read_file`. same tool and arguments already called 2 times, limit is 2

[trimmed]

## What to check next

- Read the arguments above and work out where that value came from.
- Check earlier tool results for text that may have steered the agent toward this value.
- If it is a false positive, narrow the pattern or scope it to one tool.
```

Text from the log that a server could control is escaped, so it cannot add links or headings to the report.

## Limits

- A report covers only what passed through the guard and was written to the log. It cannot show what a server did internally.
- It explains which rule fired. It does not determine why an agent made the call or whether the call was harmful.
- The log is a plain file with no tamper protection, and redacted values cannot be recovered.
- Lines that cannot be parsed are skipped and counted in the summary.

## Tests

```sh
node --test
```

12 tests, all passing on Node 24.14.0 on Windows 10.

## License

MIT

Developed by [buildwithesha.web.app](https://buildwithesha.web.app/) for [AgenticMart](https://agenticmart.org)
