# The cold-start pass

The test suite proves preflight does what it claims. It cannot tell you whether a
stranger can work out *how*, and that is the thing this repository is actually
selling: a person who has never seen preflight should be able to gate a plugin
folder from the documentation alone.

So once per release, somebody who does not know this codebase is asked to do it,
and every place they stumble is written down. A stumble is a defect in the
documentation or the messages, not in the reader.

## How to run one

1. Pick a reader. An agent works well and is what the briefing is written for
   (`briefing.md`); a human colleague works better if you can get one.
2. Give them **only** what a stranger would have: a shell, an empty directory, and
   the published documentation. **They must not have the repository checkout.**
   If the reader can read `src/`, they will resolve their own confusion from the
   source, and the pass measures nothing.
3. Have them work `tasks.md` in order, narrating as they go — what they expected,
   what they tried, where they had to stop and re-read.
4. Write the friction log to `reports/YYYY-MM-DD-<label>.md`. Use the template at
   the bottom of this file.

Scripted, with the Claude Code CLI:

```
claude -p "$(cat scripts/coldstart/briefing.md)" --add-dir /path/to/empty/scratch
```

Run it from outside the checkout, or the reader will find the source.

## What a good report looks like

Not a pass/fail. The output is a list of moments where the reader's model of the
tool and the tool's actual behaviour came apart, each one pinned to the line of
documentation that caused it. A pass that finds nothing is a suspicious pass —
say so explicitly in the report rather than leaving it blank, so a future reader
can tell "nothing found" from "never run".

Severity, and what it means for the release:

| | |
|---|---|
| **blocker** | The reader could not complete the task at all from the docs. Fix before release. |
| **friction** | They completed it, but had to re-read, guess, or backtrack. Fix if cheap. |
| **polish** | They noticed something off but it cost them nothing. Log it and move on. |

## Report template

```markdown
# Cold-start pass — YYYY-MM-DD

- **Reader:** (model + effort, or the person)
- **Given:** (README only / README + MANUAL / installed from PyPI or from git)
- **Version under test:** (`preflight --version`)
- **Tasks completed:** n of 7

## Findings

### 1. <one-line summary> — blocker | friction | polish
- **Task:** which task in tasks.md
- **Expected:** what the reader thought would happen
- **Happened:** what actually did
- **Source:** the doc line or the message that caused it
- **Fix:** the smallest change that would have prevented it

## Nothing-found note

(If a task produced no findings, say so here. Silence is not evidence.)
```
