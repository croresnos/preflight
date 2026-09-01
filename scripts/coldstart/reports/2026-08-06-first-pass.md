# Cold-start pass — 2026-08-06

- **Reader:** Claude Opus 5, given `docs/` and an installed venv, no repository checkout
- **Given:** README + MANUAL, preflight installed from a local build
- **Version under test:** 0.6.0
- **Tasks completed:** 7 of 7
- **Source read:** none. The reader confirmed it never opened the implementation.

Findings 2, 6 and 12 were independently reproduced by hand after the pass. The
rest are recorded as reported.

---

## Findings

### 1. The documented install command does not resolve — blocker
- **Task:** 1
- **Expected:** `pip install preflight-gate` installs it, per README and MANUAL §2 and §13.1.
- **Happened:** `ERROR: No matching distribution found for preflight-gate`. PyPI is reachable — `pip index versions preflight` returns `0.2.0, 0.1.1, 0.1.0`, confirming the taken-name story. `preflight-gate` is simply not there.
- **Source:** README install section and MANUAL §2, both stating the command unconditionally with no "not yet published" note.
- **Fix:** Publish, or add one line: "Not on PyPI yet — install from the repo: `pip install git+https://github.com/croresnos/preflight`."

### 2. `try --force` destroyed a file the manual promises it will never touch — blocker
- **Task:** 4
- **Expected:** MANUAL §9.6: "It **refuses a folder it did not write whatever state that folder is in**, because overwriting somebody's own `host.py` is the one irreversible thing this command could do."
- **Happened:** A folder containing only a hand-written `host.py` was refused with `already exists and is not empty. Pass --force to write into it anyway`. Passing `--force` overwrote it and exited 0.
- **Source:** MANUAL §9.6. The two refusals *are* correctly distinguished — the sandbox path says "already a preflight sandbox … `--force` to **reset** it" — so the code knows the difference. Only the guarantee, and the second message's "write into it anyway", are wrong.
- **Fix:** Pick one. Either make `--force` refuse a folder `try` did not write, making §9.6 true, or change §9.6 and have the message say plainly that `--force` overwrites `host.py` and `plugins/`.
- **Reproduced by hand:** yes.

### 3. A saved rule reported as "in force" was then ignored for the thing checked — friction
- **Task:** 7
- **Expected:** MANUAL §12: from then on `check` and `demo` apply the rule without being told.
- **Happened:** `settings refuse write` confirmed the write and `settings` listed it as live with origin `project`. The next `check` printed `preflight: ignoring …preflight.settings.json / it sits above the folder being inspected, in a directory with no sign of having been set up by hand` and exited 0. `touch .preflight-root` fixed it instantly.
- **Source:** §12.3 does document the marker rule, but the `settings` screen answers "what is in force" rather than "will this apply", and the ignore message says "no sign of having been set up by hand" without naming a single sign.
- **Fix:** Name the markers in the message — `no .git, .hg, pyproject.toml or .preflight-root here; create one to have this apply` — and warn at write time when writing into an unmarked directory, since that is when the user is standing there.

### 4. §6 "Adopting a package you did not write" stops one step short of loading — friction
- **Task:** 5
- **Expected:** §6 is titled for exactly this task, so it should end with the package loading.
- **Happened:** It ends at `check`. An ordinary package with no `create_plugin` and no `manifest` attribute passed `create` and passed `check` with exit 0, then the gate refused it: `failed to load plugin package 'local.notepad' … module 'notepad' has no attribute 'create_plugin'`. The reader inferred the need for an adapter from §3.1 plus §10.2 and wrote one; it loaded first try.
- **Source:** §6. Every worked example elsewhere is a package that *does* import preflight — the opposite of §6's premise.
- **Fix:** ~15 lines in §6: the adapter file, why it must live inside the trusted root, and the flat statement that a package with no `manifest` attribute cannot load however good its `manifest.json` is.

### 5. `check` said "Paperwork is consistent", exit 0, on a package that could not load — friction
- **Task:** 5
- **Expected:** §13.4 recommends `check` in CI so a startup refusal is caught at review time; §14 row 21 claims it reaches the gate's verdict.
- **Happened:** With no `create_plugin` anywhere, `check` resolved the module, printed `Paperwork is consistent`, exit 0. The gate then refused it. `check` verifies the *module* half of the entrypoint and says nothing about the `:attribute` half — the first thing a newcomer gets wrong.
- **Source:** §14 row 21 and §13.4, both technically scoped to preload checks but reading broader.
- **Fix:** One sentence under §9.1: `check` cannot confirm the `:attribute` half of the entrypoint, or that the object satisfies `Plugin` — both need an import, and those are rows 16–17, which only the gate reaches.
- **Note:** this is a sibling of the shadowing divergence fixed in this same batch — same family, different half of the entrypoint string.

### 6. `check`'s suggested next command drops the path and fails — friction
- **Task:** 5
- **Expected:** Copy-paste the command the tool just printed.
- **Happened:** `check plugins/notepad` ended with `preflight create notepad`. Run verbatim: `preflight: '…\notepad' does not exist.` It echoed the basename, not the path given. `create`'s own "Next:" line has the opposite habit and prints a full path that works.
- **Fix:** Echo the path as the user typed it.
- **Reproduced by hand:** yes.

### 7. `try`'s break instructions are PowerShell-only — friction
- **Task:** 4
- **Expected:** "commands for your shell" (§9.6). The reader was on Windows in Git Bash.
- **Happened:** Correctly detected Windows, emitted PowerShell, and `bash: Remove-Item: command not found`. All six commands were translated by hand; all three breaks and undos then reproduced the documented output exactly.
- **Source:** Detection is per-OS, not per-shell, and Git Bash on Windows is a large population.
- **Fix:** A portable form for all three, or both flavours under `# PowerShell:` / `# bash:`. Forward slashes work in both.

### 8. The generated host uses `result.get()`; the manual only documents `result.plugins.get()` — friction
- **Task:** 5
- **Happened:** `try`'s `host.py` calls `result.get("weather")`. §5's "Programmatically:" block reads as the complete surface of the result object and lists `result.plugins`, `result.loaded`, `result.refused` — no `result.get`. The reader stopped to check whether the sandbox was using something real. Both work.
- **Fix:** Add `result.get(plugin_id)` to the §5 list, or drop it from the generated host. The tool's own sample code currently teaches an API the manual does not contain.

### 9. README names `load_manifest_file`, which is not importable — polish
- **Happened:** README's threat model says "`load_manifest_file` accepts a custom `importer`". `from preflight import load_manifest_file` → ImportError. It appears nowhere in the MANUAL.
- **Fix:** Rename to whatever it is now, or drop the identifier and say "a host that supplies its own importer".

### 10. No API reference, so the reader resorted to `dir(preflight)` — polish
- **Happened:** `dir(preflight)` shows 30 public names including `Inspection`, `inspect_package`, `format_inspection`, `LoadReport`, `RegisteredPlugin` — an entire inspection surface with no documentation. `LoadReport` is the type of the thing every example prints and the manual never names it.
- **Fix:** A short §16 table of exported names, one line each. "Internal, not supported" is a fine answer for half of them and better than silence.

### 11. `create`'s entrypoint guess is smarter than every transcript shows — polish
- **Happened:** §6 says it "guesses the entrypoint from the folder name" and every transcript shows `weather.plugin:create_plugin`. With no `plugin.py` present it wrote `notepad:create_plugin`, resolving to `__init__.py`. Correct, and better than expected — but it caused a re-read.
- **Fix:** One clause: "it points at `<name>.plugin` when a `plugin.py` is there, and at the package itself otherwise."

### 12. The README's `demo` transcript is missing three lines the command prints — polish
- **Happened:** The real run ends with three more lines than the README block: `The 3 lines above reading 'top-level plugin code is executing' are / tripwires: the first statement in a plugin package. 2 of the 3 refused / plugins never printed one, because they never got an import.`
- **Fix:** Re-capture the transcript.
- **Reproduced by hand:** yes. **Note:** `tests/test_transcripts.py` does *not* catch this, by design — its comparison is one-directional, so a line the CLI gained never fails. This finding is the first measured cost of that tradeoff. Exact-equality comparison would catch it, at the price of unwrapping the hand-wrapped lines in the docs.

### 13. Plain `demo` does not explain why one refusal arrives late — polish
- **Happened:** `demo --refuse destructive` prints a five-line explanation of the declared-vs-concealed distinction. Plain `demo` — the command a first-timer runs — does not.
- **Fix:** A two-line version in plain `demo`, or end it with `Try: preflight demo --refuse destructive`.

### 14. `check` with no manifest exits 1 while the text disclaims any verdict — polish
- **Happened:** Exit 1, with body text reading `That is not a verdict on the package; it is the absence of one.` Defensible, but the prose and the exit code say opposite things on one screen, and §7.5 does not mention the case.
- **Fix:** A parenthetical in §7.5: a package with no manifest exits 1, because a host would refuse it.

---

## Nothing-found note

- **Task 2 (say what it is for)** — no findings, and the strongest thing in the docs. The answer is README line 3, in bold, before anything else. The reader formed no wrong idea and read nothing twice. Distance to a correct one-sentence summary: one line.
- **Task 6 (predict a refusal)** — no findings. The prediction, written before running, matched **verbatim**: the refusal sentence, the `never imported` stage, the tally, the *absence* of the tripwire, the `X` vs `!` marker change, the `Policy(...)` line, and exit 1. §7.2 and §9.2 are precise enough to predict output word for word.
- **Task 4 undos** — all three restored state exactly. The `sys.dont_write_bytecode = True` comment in the generated host anticipated a stale-`.pyc` trap that would otherwise have cost twenty minutes.
- **Also verified, no findings:** the `sys.path` omission error prints a paste-ready `sys.path.insert(...)` with backslashes already escaped. `check <dir-of-packages>` reports per-package. `settings --as-python` emitted the correct `Policy`. `settings refuse --clear` worked. `python -m preflight` works as claimed. §2's warning that "the command on your `PATH` belongs to a different environment" is not hypothetical — it caught a real mismatch during this pass; `preflight try`'s `python host.py` instruction carries no such caveat and is where someone will get bitten.
