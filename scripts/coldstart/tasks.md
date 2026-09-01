# Cold-start tasks

Work these in order. Stop at the first one you cannot complete and say so — an
abandoned task is the most valuable result this exercise produces.

Every task is something the documentation already promises. If you cannot do it
from the documentation, that is the finding.

---

### 1. Install it and prove it is there

Install preflight the way the documentation tells you to, and confirm which
version you have.

*Watch for:* whether the install instruction works verbatim, and whether the
command name matches the package name.

### 2. Say what it is for, in one sentence

Before running anything else, read enough to write one sentence: what problem
does this solve, and who for? Note how long that took and what you had to read.

*Watch for:* whether you had to read past the first screen to answer. Whether you
formed a wrong idea first and corrected it.

### 3. Watch it refuse something

Run the bundled demonstration. Then explain, without looking anything up: why
were some plugins refused before running and others only after?

*Watch for:* whether the output makes that distinction legible on its own, or
whether you had to go back to the prose to decode it.

### 4. Break it on purpose, then put it back

Create the sandbox and work all three of the documented breaks — and each undo.
Confirm the sandbox is back in its working state at the end.

*Watch for:* any break whose undo does not restore the previous state. Any
instruction that assumes a shell or OS you are not using.

### 5. Gate a package that has never heard of preflight

Make a small Python plugin package of your own — one that does not know preflight
exists. Write a manifest for it, check it, and get it loading through a real host.

*Watch for:* this is the longest task and the real one. Every place you had to
guess at a required field, a file layout, or what the host is supposed to look
like is a finding.

### 5a. Adopt the same package the other way

Task 5 gave you a choice you may not have noticed you were making: whether the
package states its own manifest, or whether preflight adapts it from the file.
Do the other one now — if you wrote an adapter, redo it without; if preflight
adapted it, run `create --adapter` on a fresh copy and get it loading.

*Watch for:* whether the documentation made the choice visible before you made
it, whether you could tell from the output afterwards which one you had, and
whether you can say in one sentence what the second one buys.

### 6. Predict a refusal before you cause it

Deliberately make the package from task 5 refusable. Before you run anything,
write down the message you expect. Then run it and compare.

*Watch for:* whether the message told you what to change without you needing to
search. If it named the problem but not the fix, that is friction.

### 7. Save a rule so you stop retyping it

Save a refusal rule so it applies without a flag. Confirm it is in force, then
confirm you can find where it was written and remove it again.

*Watch for:* whether it is clear which file the rule went into, whether the rule
applies to the thing you expected, and whether you can tell it apart from a
setting that does *not* apply.

---

## What to record as you go

For each task: what you expected, what happened, and every moment you had to stop
and re-read. Verbatim quotes of confusing output are more useful than a summary
of it. If you find yourself guessing, record the guess and whether it was right.
