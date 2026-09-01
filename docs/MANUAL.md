# preflight — the manual

The [README](../README.md) argues for preflight and specifies it. This file is the
part where you sit down and use it: install, first working host, first refusal, and
then a section for every message it can print at you and what to do about each one.

Everything quoted here is copied from a real run. Where a message contains an
absolute path, the path is replaced with `<root>` and nothing else is changed —
your own output prints the real directory.

**Contents**

1. [What you are about to build](#1-what-you-are-about-to-build)
2. [Install](#2-install)
3. [Your first host, start to finish](#3-your-first-host-start-to-finish)
4. [Refusing things on purpose](#4-refusing-things-on-purpose)
5. [Reading the report](#5-reading-the-report)
6. [Adopting a package you did not write](#6-adopting-a-package-you-did-not-write)
7. [Every message, and what to do about it](#7-every-message-and-what-to-do-about-it)
8. [Questions that come up in practice](#8-questions-that-come-up-in-practice)
9. [Command-line reference](#9-command-line-reference)
10. [The manifest format](#10-the-manifest-format)
11. [Worked examples](#11-worked-examples)
12. [Saving your settings](#12-saving-your-settings)
13. [preflight inside an agent](#13-preflight-inside-an-agent)
14. [What it checks, in order — and the test for each](#14-what-it-checks-in-order--and-the-test-for-each)
15. [Why it exists](#15-why-it-exists)

---

## 1. What you are about to build

preflight goes **inside a program that loads plugins**. It reads each plugin's
`manifest.json` and decides whether that plugin may be imported — before any of its
code runs. Your application calls it at startup, every startup.

That is the whole product. The `preflight` command in your terminal exists to help
you write a manifest for a package that does not have one yet; it is an on-ramp, and
it protects nothing at runtime because nothing of it is running at runtime.

Two things to be clear about before you spend an afternoon on this:

- **It enforces declarations. It does not detect concealment.** A plugin that
  declares a read-only tool and quietly does something else will pass. preflight is
  a permission system, in the same family as a browser extension manifest — not a
  scanner, and not a sandbox. See [Threat model](../README.md#threat-model).
- **The manifest is the price of admission you set.** You are not hoping plugin
  authors happen to ship one. Your loader refuses to import anything without one,
  which is what makes writing one worth their while.

If you want to vet a package you downloaded from the internet, preflight is the
wrong tool and no amount of configuration will change that.

---

## 2. Install

```
pip install preflight-gate
```

Python 3.11 or newer. The only dependency is pydantic.

**The distribution is `preflight-gate`; everything else is `preflight`** — the
import, the command, the manifest schema. PyPI's `preflight` is an unrelated Django
project last released in 2015, so that one name was never available. You only ever
type `preflight-gate` once.

Check it landed:

```
preflight --version
```

If that prints a version you did not expect, or nothing at all, the command on your
`PATH` belongs to a different environment. Ask the interpreter you are actually
about to run your host with:

```
python -c "import preflight, sys; print(preflight.__version__, sys.executable)"
```

Then watch it refuse things, which takes about four seconds and is the fastest way
to see the shape of the thing:

```
preflight demo
```

That loads five bundled example plugins and refuses three of them. It runs from any
directory — you do not need to be inside a checkout.

Those are somebody else's plugins, failing in ways they chose. For one of your own
to take apart:

```
preflight try weather-sandbox
cd weather-sandbox
python host.py
```

That writes a working host, one plugin, and its manifest, then names three ways to
break them. Section 3 builds the same thing by hand, which is worth doing once;
`try` is for when you would rather start from something that already runs.

`try` writes plugin code. `create` ([section 6](#6-adopting-a-package-you-did-not-write))
deliberately does not — a manifest
records what *you* permit, so preflight inventing it would defeat the point. Treat
what `try` writes as a sandbox, not as the start of something you ship.

---

## 3. Your first host, start to finish

### 3.1 The layout

A plugin is an ordinary importable Python package with a `manifest.json` next to its
code. All the plugins live under one directory, and **that directory is your
security boundary**:

```
myapp/
├── host.py
└── plugins/                 <- the trusted root
    └── greeter/
        ├── __init__.py      <- required, even if empty
        ├── plugin.py
        └── manifest.json
```

`__init__.py` is not optional. Without it the folder is a namespace package, which
has no file on disk to check against the trusted root, and preflight refuses what it
cannot locate. An empty file is fine.

### 3.2 The plugin

`plugins/greeter/plugin.py` — an object with a `manifest` attribute, and a factory
function to build it:

```python
from preflight import PluginManifest

_MANIFEST = {
    "plugin_id": "greeter",
    "name": "Greeter",
    "module_version": "1.0.0",
    "tools": [{"name": "greeter.hello", "risk": "read"}],
}


class Greeter:
    def __init__(self):
        self.manifest = PluginManifest.model_validate(_MANIFEST)

    def hello(self, who: str) -> str:
        return f"Hello, {who}."


def create_plugin() -> Greeter:
    return Greeter()
```

`plugins/greeter/manifest.json` — the same plugin block, plus how the package should
be treated:

```json
{
  "package_id": "example.greeter",
  "core_api_version": "1.0",
  "visibility": "public",
  "release_ring": "stable",
  "entrypoint": "greeter.plugin:create_plugin",
  "plugin": {
    "plugin_id": "greeter",
    "name": "Greeter",
    "module_version": "1.0.0",
    "tools": [{"name": "greeter.hello", "risk": "read"}]
  }
}
```

The `plugin` block appears twice on purpose — once in the file, once in the running
object — and preflight checks that they are equal after importing. That is what
turns the manifest from documentation into something enforced. If you change one,
change both. Field-by-field reference: [The manifest
format](#10-the-manifest-format).

The minimum a manifest can contain is `package_id`, `visibility`, `release_ring`,
`entrypoint`, and a `plugin` block with `plugin_id`, `name`, and `module_version`.
Everything else has a default, including `tools`, which defaults to none.

### 3.3 The host

`host.py`:

```python
import sys
from pathlib import Path

from preflight import load_plugins

PLUGINS = Path(__file__).resolve().parent / "plugins"

# preflight never modifies sys.path. Making the plugin directory importable is
# the host's job -- a library that mutates global import state as a side effect
# of a security check is worse than one that documents the requirement.
sys.path.insert(0, str(PLUGINS))

result = load_plugins(PLUGINS, allow=["example.greeter"])

print(result)
print(result.plugins["greeter"].hello("world"))
```

### 3.4 Run it

```
python host.py
```

```
preflight | plugins\ | 1 package found

  LOADED   greeter  Greeter 1.0.0 - 1 tool

  1 loaded, 0 refused
Hello, world.
```

That is a working gate. Three things about it are load-bearing:

- **`allow` is required and has no wildcard.** A package sitting in the folder but
  absent from `allow` is discovered, reported, and never imported. Discovery saves
  you the `for` loop; the allowlist is what keeps an unexpected folder inert.
- **The order of `allow` is the order things load,** and the first plugin to claim a
  tool name keeps it. Precedence is something you wrote down, not something the
  filesystem decided alphabetically.
- **The directory you pass is the security boundary.** Every manifest must be inside
  it and every entrypoint must resolve to a file inside it. Point it at a directory
  anyone can write to and none of the rest matters.

### 3.5 Refusal is data, not an exception

`load_plugins` does not raise when a plugin is refused. It returns a report, and
your host decides what a refusal means. That is deliberate — one bad plugin should
not take down the application — but it means this line is a trap:

```python
print(result.plugins["greeter"].hello("world"))  # KeyError if greeter was refused
```

In anything real, ask first:

```python
greeter = result.plugins.get("greeter")
if greeter is None:
    ...  # log result.refused and carry on, or exit, or fall back
```

`result.plugins` holds only what loaded. `result.refused` holds the outcomes that
did not, each with a `reason` and a `code_ran` flag.

`load_plugins` *does* raise, before loading anything, in two cases the host got
wrong rather than the plugin: the directory does not exist, and the directory is not
on `sys.path`. Both are in [section 7](#7-every-message-and-what-to-do-about-it).

---

## 4. Refusing things on purpose

Add a second plugin, `auditor`, whose paperwork is perfect and which honestly
declares one destructive tool:

```json
"tools": [{"name": "auditor.purge_logs", "risk": "destructive"}]
```

With no policy, it loads. Nothing is wrong with it:

```
preflight | plugins\ | 2 packages found

  LOADED   greeter  Greeter 1.0.0 - 1 tool
  LOADED   auditor  Auditor 1.0.0 - 1 tool

  2 loaded, 0 refused
```

Now say your application does not accept destructive tools:

```python
from preflight import Policy, ToolRisk, load_plugins

result = load_plugins(
    PLUGINS,
    allow=["example.greeter", "example.auditor"],
    policy=Policy(refuse_tool_risks={ToolRisk.DESTRUCTIVE}),
)
```

```
preflight | plugins\ | 2 packages found

  LOADED   greeter  Greeter 1.0.0 - 1 tool
  REFUSED  auditor  never imported
                    package 'example.auditor' declares tool 'auditor.purge_logs' with risk 'destructive', which this host refuses

  1 loaded, 1 refused -- 1 of the 1 stopped before any of their code ran
```

Same plugin, same manifest, different host. `auditor` was refused for being honest
about something you did not want, and its code never ran.

The risk vocabulary is `read`, `write`, `destructive`, `financial`, `credential`,
`security`, `public_posting`, and `sensitive_disclosure`. It is asserted by the
plugin, not measured by preflight — see [Tool risk
levels](#101-tool-risk-levels).

Everything is a keyword argument and there is no configuration file, because a
settings file living next to your plugins would be a file a plugin could write. The
defaults are the strictest values available, so a call that passes no `Policy` at
all is the safest call you can make. Other settings: [Settings](../README.md#policy).

---

## 5. Reading the report

The middle column of a refusal is the part worth your attention.

**`never imported`** — refused while still inert on disk. Nothing of it ran. This is
what preflight is for.

**`imported, then rejected`** — the plugin's code executed before it was turned
away. Refusing it kept it out of your registry; it did not keep it from running.
Two things land here: checks that can only be made against a live object (does it
implement the protocol, does its runtime manifest match its file), and packages
whose `__init__.py` ran and then raised.

The summary line counts them:

```
  1 loaded, 1 refused -- 1 of the 1 stopped before any of their code ran
```

`0 of the 1` is not a failure of preflight; it is preflight telling you the truth
about a check that could not be made any earlier. `Outcome.code_ran` is recorded
from the run itself, not inferred from which error came back, which is why that
number is worth believing.

Programmatically:

```python
result.plugins  # {plugin_id: instance} -- only what loaded
result.get("weather")  # one instance, or None if it did not load
result.loaded  # the outcomes that loaded
result.refused  # the outcomes that did not
result.text()  # the report above, as a string
for outcome in result.refused:
    outcome.folder  # the directory name
    outcome.reason  # the refusal message
    outcome.code_ran  # True if the plugin's code executed first
    outcome.stage  # "never imported" | "imported, then rejected"
for outcome in result.loaded:
    outcome.self_reported  # False if a bare entrypoint waived check 17 (6.1)
```

`result.get(id)` rather than `result.plugins[id]` is the habit worth forming, and
the sandbox `try` writes uses it for a reason: a refusal is an ordinary outcome, so
the plugin you were expecting may simply not be there, and `.get` makes you decide
what that means instead of raising `KeyError` at you.

**Nothing in `load_plugins` stops your program.** A refusal is data. If your host
cannot run without its plugins, say so — the generated `host.py` ends with
`sys.exit(1 if result.refused else 0)`, which is the smallest version of that
decision.

---

## 6. Adopting a package you did not write

Sometimes you decide to gate a package that has never heard of preflight. Then you
write the manifest, because you are the one setting the terms:

```
preflight create plugins/weather
```

<!-- transcript: preflight create plugins/weather | setup=unmanaged_weather -->
```
wrote <root>\plugins\weather\manifest.json

  This manifest records what you PERMIT this package to do. preflight
  did not read its code and has not checked whether the two agree.
  An empty `tools` list means it may expose none.

  This package does not report its own manifest, so preflight will
  adapt it using this file. Everything else is checked as usual.
  To have the package state its own manifest and be checked against
  it, run again with --adapter.

  Next:
      preflight check <root>\plugins\weather
```

It writes a minimal manifest with `tools: []` — permitting nothing — and guesses the
entrypoint by looking at what is on disk: `<name>.plugin` when the package has a
`plugin.py`, the package itself otherwise, and with no `:attribute` half at all
when neither file defines a `create_plugin` to point at. Open it and write down
what you actually intend to allow. `preflight check` then reads it back without
importing anything:

```
preflight check | weather\ | nothing was executed

  manifest      valid
  package id    local.weather
  plugin        weather 0.1.0  (id: weather)
  tier          public, stable ring
  entrypoint    weather.plugin:create_plugin
                -> weather\plugin.py  (inside this folder)

  declares no tools

  Paperwork is consistent. preflight did not run this code and cannot
  tell you whether it does what it says.
```

"Paperwork is consistent" is a statement about the manifest and nothing else. The
last two lines are there because that distinction is the whole point.

`check` exits `0` when the package would load, `1` when it would be refused, and `2`
when you pointed it at something that is not a directory — so it works in a script
without anyone reading the output.

### 6.1 The entrypoint has two shapes, and this is the one that matters here

A package written for preflight ends its entrypoint with `:create_plugin`, and the
gate then requires the object that comes back to report a manifest **equal to the
one in the file** — check 17. That is a real check, and it is the reason the two
descriptions are written out twice.

A package that has never heard of preflight was never going to return a
`PluginManifest`. So its manifest names the module and stops:

```json
"entrypoint": "weather"
```

preflight imports that module and adapts it, using the `plugin` block from the
manifest as its description. Everything else is unchanged — the manifest is still
confined to the trusted root, the module is still resolved to a file inside it
before anything is imported, and the tools the host advertises still come from
this file rather than from the object. The one check you do not get is 17, because
there is no second statement to compare against. That is a **waiver, not a pass**,
and it is visible wherever the package is reported:

```
  LOADED   weather  Weather 0.1.0 - 1 tool  (adapted; manifest not self-reported)
```

The host then uses it exactly as it would any other plugin — `result.get("weather")`
returns an object that carries the manifest and forwards everything else to your
module:

```python
result = load_plugins(PLUGINS, allow=["local.weather"])
result.get("weather").forecast("tomorrow")  # your module's own function
```

**If you own the package, take the check.** `preflight create <folder> --adapter`
writes a `plugin.py` stating the same manifest in Python, points the entrypoint at
it, and from then on a version bumped in one file and not the other is a refusal.
That duplication is not redundancy; it is the thing check 17 compares. It will not
overwrite a `plugin.py` you already have.

**Neither command protects a running application.** Writing a manifest is a decision
you record; enforcing it is `load_plugins`, in your host, at startup. Full CLI
reference including `--refuse`: [Command-line
reference](#9-command-line-reference).

---

## 7. Every message, and what to do about it

### 7.1 Errors raised by `load_plugins`

These stop your program. They mean the host is misconfigured, not that a plugin is
bad.

<table>
<tr><th>Message</th><th>What it means, and what to do</th></tr>
<tr><td><code>NotADirectoryError: plugin directory '&lt;root&gt;' does not exist</code></td>
<td>The path you passed is not there. Usually a relative path resolved against the
wrong working directory — build it from <code>Path(__file__).resolve().parent</code>
rather than a bare string.</td></tr>
<tr><td><code>RuntimeError: '&lt;root&gt;' is not on sys.path, so none of its plugins can be imported.</code></td>
<td>You skipped the <code>sys.path.insert</code> line. preflight will not do it for
you; the error prints the exact line to paste. Without this check you would instead
get a pile of "no file on disk" refusals that read like a preflight bug.</td></tr>
<tr><td><code>RuntimeError: unrecognised host platform '&lt;name&gt;'; pass platform= explicitly</code></td>
<td>You are on an OS preflight does not have a name for. Pass
<code>Policy(platform=...)</code>.</td></tr>
<tr><td><code>KeyError</code> on <code>result.plugins[...]</code></td>
<td>Not a preflight error. The plugin was refused, so it is not in the dict — read
the report printed above it, and see <a href="#35-refusal-is-data-not-an-exception">3.5</a>.</td></tr>
</table>

### 7.2 Refusals that happen before the plugin runs

These appear in the report as `never imported`. Your program keeps going.

<table>
<tr><th>Reason</th><th>What it means, and what to do</th></tr>
<tr><td><code>package '&lt;id&gt;' is not in the explicit build allowlist</code></td>
<td>The <code>package_id</code> in the manifest is not in your <code>allow</code>
list. Note the message quotes the id <em>from the manifest</em> — if you typo'd the
allowlist, this message shows the correct id and it looks confusingly right. Compare
the two strings character by character.</td></tr>
<tr><td><code>invalid plugin manifest '&lt;path&gt;': &lt;parse error&gt;</code></td>
<td>The file is not valid JSON. The rest of the message is Python's own parse error
with a line and column. Usually a trailing comma or a single quote.</td></tr>
<tr><td><code>invalid plugin manifest '&lt;path&gt;':</code><br><code>2 problems with this manifest:</code><br><code>&nbsp;&nbsp;visibility&nbsp;&nbsp;&nbsp;&nbsp;Field required</code><br><code>&nbsp;&nbsp;release_ring&nbsp;&nbsp;Field required</code></td>
<td>Valid JSON, wrong shape. One line per bad field, capped at six with the
remainder counted. <code>Field required</code> means you left something out;
<code>Extra inputs are not permitted</code> means you misspelled a field name or
invented one. The schema is closed on purpose: an unrecognised field is a refusal,
not a shrug, because silently ignoring part of a permission document is how
permission documents become fiction.</td></tr>
<tr><td><code>invalid plugin manifest '&lt;path&gt;': This is a manifest.json, but not one of preflight's. It has none of the fields preflight requires (package_id, visibility, release_ring, entrypoint, plugin), and &lt;n&gt; that preflight does not recognise.</code></td>
<td>The folder holds somebody else's <code>manifest.json</code> — a browser
extension, a Figma plugin, a web app. Nothing is wrong with the file and preflight
is not calling it broken. Either that folder is not a preflight package, or you have
yet to write one; see <a href="#6-adopting-a-package-you-did-not-write">6</a>, and
read the warning there about <code>--force</code> before you overwrite theirs.</td></tr>
<tr><td><code>plugin manifest '&lt;path&gt;' exceeds &lt;n&gt; bytes</code></td>
<td>Over 256 KiB by default. Refused before it is parsed. Raise it with
<code>Policy(max_manifest_bytes=...)</code> if you genuinely need to.</td></tr>
<tr><td><code>plugin manifest must be inside the trusted plugin root '&lt;root&gt;'</code></td>
<td>A symlink or a path escaping the directory you nominated.</td></tr>
<tr><td><code>cannot read plugin manifest '&lt;path&gt;': ...</code></td>
<td>Permissions, or the file vanished between discovery and reading.</td></tr>
<tr><td><code>entrypoint module '&lt;name&gt;' has no file on disk, so it cannot be shown to live inside the trusted plugin root '&lt;root&gt;'</code></td>
<td>The most common first-timer refusal, and it has four causes. You do not have to
work out which is yours: preflight looks at the folder and prints a second line
naming it. The four are listed separately below.</td></tr>
<tr><td><code>that folder is on disk but has no __init__.py, so Python treats it as a namespace package and it resolves to no single file. Create an empty '&lt;path&gt;'.</code></td>
<td>Do exactly that. An empty file is enough — it is what makes Python treat the
folder as a package rather than a loose directory that happens to hold
<code>.py</code> files.</td></tr>
<tr><td><code>no '&lt;name&gt;\__init__.py' and no '&lt;name&gt;.py' inside that root. Check the entrypoint in manifest.json against the names on disk.</code></td>
<td>A typo, or a folder that was renamed after the manifest was written. A folder
called <code>hello_greeter</code> cannot satisfy
<code>greeter.plugin:create_plugin</code>; the two names are one string in two
places and both have to agree. (The separator is your platform's — <code>/</code>
on macOS and Linux.)</td></tr>
<tr><td><code>the file is there, but '&lt;root&gt;' is not on sys.path, so the import system cannot see it. preflight never modifies sys.path for you -- add sys.path.insert(0, '&lt;root&gt;') before loading.</code></td>
<td>Nothing is wrong with the package. Paste the line it gives you.
<code>load_plugins</code> catches this earlier and more loudly (see 7.1); you only
reach it here by driving <code>PluginRegistry</code> yourself.</td></tr>
<tr><td><code>the file is there and that root is on sys.path, so something earlier on sys.path is answering to '&lt;name&gt;' first. Rename the plugin folder to a name no installed package already uses.</code></td>
<td>Your plugin folder is named after a module compiled into the interpreter
(<code>time</code>, <code>sys</code>, <code>_socket</code>) or frozen into it
(<code>os</code>). Those are answered by <code>sys.meta_path</code> before
<code>sys.path</code> is consulted at all, so they report no file, and the name is
taken in every process whatever a host does to <code>sys.path</code>. Your
paperwork is fine and no amount of fixing it will help. Rename the folder and the
<code>entrypoint</code> together. A folder named after a <em>pure-Python</em>
stdlib module (<code>json</code>, <code>types</code>) does not reach this message —
it resolves to a real file, and is refused by the row below instead.</td></tr>
<tr><td><code>entrypoint module '&lt;name&gt;' resolves to '&lt;path&gt;', which is outside the trusted plugin root '&lt;root&gt;'</code></td>
<td>The entrypoint points at something real but out of bounds — a standard library
module, or an installed package. A plugin <em>folder</em> named after a pure-Python
stdlib module (<code>json</code>, <code>types</code>) lands here too: whichever copy
the import system already holds under that name is the one it hands back, and it is
not yours. This is the check the whole project exists for. It is not a configuration
problem; do not widen the root to make it go away.</td></tr>
<tr><td><code>package '&lt;id&gt;' does not support platform '&lt;name&gt;'</code></td>
<td>The manifest's <code>supported_platforms</code> excludes the OS you are on.</td></tr>
<tr><td><code>package '&lt;id&gt;' declares tool '&lt;tool&gt;' with risk '&lt;risk&gt;', which this host refuses</code></td>
<td>Working as intended: your <code>Policy(refuse_tool_risks=...)</code> stopped it.
Nothing is wrong with the plugin.</td></tr>
<tr><td><code>plugin '&lt;id&gt;' is already registered</code></td>
<td>Two packages claim the same <code>plugin_id</code>. The first one in
<code>allow</code> keeps it.</td></tr>
<tr><td><code>duplicate tool name '&lt;tool&gt;' in package '&lt;id&gt;'</code></td>
<td>One manifest lists the same tool twice.</td></tr>
<tr><td><code>tool name collision: '&lt;tool&gt;' is already owned by '&lt;id&gt;'</code></td>
<td>Two packages claim the same tool name. Order in <code>allow</code> decides who
wins, which is why that order is yours to choose.</td></tr>
<tr><td><code>&lt;edition&gt; build cannot load '&lt;id&gt;' with visibility '&lt;v&gt;'</code><br>
<code>&lt;edition&gt; build cannot load '&lt;id&gt;' from the '&lt;ring&gt;' release ring</code></td>
<td>Only if you set <code>Policy(edition=...)</code>. Most hosts never do — see
<a href="#103-release-tiers-optional">Release tiers</a>.</td></tr>
<tr><td><code>entrypoint module '&lt;name&gt;' is a standard library module name. A host that has already imported '&lt;name&gt;' refuses this package for resolving outside the trusted plugin root '&lt;root&gt;'; one that has not imports this folder in the standard library's place, for the rest of the process. Rename the plugin folder and the entrypoint together.</code></td>
<td><strong>Printed by <code>preflight check</code>, not by the gate.</strong> The
command cannot ask the import system which copy of <code>&lt;name&gt;</code> would
win — <code>find_spec</code> on a dotted name executes the parent package, and this
command may not run a line of what it is describing. So it names both outcomes
instead of claiming the one it cannot know, and refuses either way: one of them is
a refusal at startup, and the other is your plugin silently replacing a standard
library module for the life of the process. Neither is a thing to ship.</td></tr>
</table>

### 7.3 Refusals that happen after the plugin has run

These appear as `imported, then rejected`. The plugin's code executed. It was kept
out of your registry, but it was not kept from running, and the report says so.

<table>
<tr><th>Reason</th><th>What it means, and what to do</th></tr>
<tr><td><code>failed to load plugin package '&lt;id&gt;' from &lt;path&gt;: &lt;the plugin's own exception&gt;</code></td>
<td>The plugin's own code raised. The trailing text is its exception —
<code>module 'x.plugin' has no attribute 'create_plugin'</code> means the entrypoint
names a function that is not there; anything else is a bug inside the plugin.</td></tr>
<tr><td><code>entrypoint for '&lt;id&gt;' does not implement Plugin</code></td>
<td>The entrypoint returned an object with no <code>manifest</code> attribute. If
your factory returns an instance, check that <code>__init__</code> actually sets
<code>self.manifest</code>.</td></tr>
<tr><td><code>runtime manifest for '&lt;id&gt;' is invalid:</code><br><code>1 problem with this manifest:</code><br><code>&nbsp;&nbsp;plugin_id&nbsp;&nbsp;Field required</code></td>
<td>The object's <code>manifest</code> is not a valid <code>PluginManifest</code>.
Same field-by-field list as a bad <code>manifest.json</code>, about the object your
own code returned rather than about a file. Note what is <em>not</em> said here: a
runtime manifest is never reported as belonging to another system, because there is
no file for it to belong to.</td></tr>
<tr><td><code>runtime manifest for '&lt;id&gt;' does not match its validated package manifest</code><br><code>module_version: manifest says '1.0.0', plugin reports '2.0.0'</code></td>
<td>The <code>plugin</code> block in <code>manifest.json</code> and the one in the
running object are not equal. Nearly always drift — someone bumped
<code>module_version</code> or added a tool in one place only. A line follows for each
field that differs, so there is nothing to diff by hand. List fields whose entries carry
names — <code>tools</code> above all — report membership instead of two full dumps:
<code>tools -- undeclared in the manifest: acme.weather.purge</code>, and
<code>declared differently</code> for a tool that keeps its name and changes its risk.
That last shape is the one with teeth, and it is why the two copies exist.</td></tr>
<tr><td><code>entrypoint module '&lt;name&gt;' was imported from '&lt;path&gt;', which is outside the trusted plugin root</code></td>
<td>What was resolved and what was imported are not the same file — something
changed <code>sys.modules</code> in between. Treat this as hostile.</td></tr>
</table>

### 7.4 Command-line messages

<table>
<tr><th>Message</th><th>What it means, and what to do</th></tr>
<tr><td><code>manifest      not preflight's</code></td>
<td>The folder has a <code>manifest.json</code> belonging to another system — a
Figma plugin, a browser extension, a web app. Nothing is wrong with it; preflight
just cannot read it. To adopt the package you must take that filename, and
<code>preflight create --force</code> <b>overwrites</b> the existing file. Move
theirs aside first if the tool it belongs to still needs it.</td></tr>
<tr><td><code>no manifest.json found</code></td>
<td>Not an error about the package. Run <code>preflight create &lt;folder&gt;</code>
to write down what you will permit.</td></tr>
<tr><td><code>manifest      INVALID</code></td>
<td>A preflight manifest with mistakes in it. The problems are listed by field,
capped at six with the rest counted.</td></tr>
<tr><td><code>&lt;path&gt; already exists. Pass --force to overwrite it.</code></td>
<td><code>create</code> will not overwrite a manifest by accident. Exit code 2.</td></tr>
<tr><td><code>'&lt;name&gt;' cannot be a Python package name</code></td>
<td>The folder name has a hyphen or similar, so no manifest could make
<code>import</code> work. The message suggests the corrected name. Either rename the
folder, or pass <code>--entrypoint</code> explicitly if the code lives
elsewhere.</td></tr>
<tr><td><code>entrypoint attribute '&lt;name&gt;' is not defined in &lt;file&gt;</code></td>
<td>From <code>check</code>, and listed under <em>AFTER importing it</em> because
that is when a host discovers it. The entrypoint's module resolves, but the
<code>:attribute</code> half names something that file does not define, so the
package would be imported and then refused. Either define it, or drop the
<code>:attribute</code> half so preflight adapts the module using the manifest
(&sect;6.1). Found by parsing the file, never by running it. Exit code 1.</td></tr>
<tr><td><code>module '&lt;name&gt;' has no attribute '&lt;attribute&gt;'</code></td>
<td>The same fault, reached at startup instead of at review time. This is the one
<code>check</code> exists to save you from — put it in CI.</td></tr>
<tr><td><code>&lt;path&gt; has files preflight did not write</code></td>
<td><code>try</code> writes <code>host.py</code> and <code>plugins/</code>, and it
will not write them over yours. There is no flag for this: <code>--force</code>
resets a sandbox <em>preflight wrote</em>, and does not take a folder over. Name a
folder that does not exist yet. Exit code 2.</td></tr>
<tr><td><code>&lt;path&gt; already exists, and --adapter writes that file</code></td>
<td>Same rule for <code>create --adapter</code>: it writes a
<code>plugin.py</code>, and never over one of yours. Point
<code>--entrypoint</code> at what is already in there. Exit code 2.</td></tr>
<tr><td><code>unknown risk '&lt;name&gt;'</code></td>
<td>A bad value for <code>--refuse</code>. The valid ones are listed. Exit code 2.</td></tr>
<tr><td><code>not a directory</code></td>
<td><code>check</code> was pointed at a file or a path that does not exist. Exit code 2.</td></tr>
</table>

### 7.5 Exit codes

| Code | Meaning |
|---|---|
| 0 | The package would load |
| 1 | The package would be refused |
| 2 | You asked the question wrong — bad path, bad flag, refusing to overwrite |

A package with no `manifest.json` at all exits `1`, even though the report says in as many words that this is *"not a verdict on the package; it is the absence of one."* Both are true: preflight has nothing to judge, and a host asked to load it would refuse it. The exit code answers the host's question, because that is the question a script is asking.

---

## 8. Questions that come up in practice

**Do I have to call this at startup? Can I load a plugin later?**
You can call `load_plugins` whenever you like. "Every startup" is the shape of the
argument, not a constraint in the code. What matters is that it is called *before*
anything imports a plugin by hand — an `importlib.import_module` elsewhere in your
codebase bypasses the gate entirely.

**What stops a plugin from just importing something dangerous itself?**
Nothing. preflight decides *whether* to import a package; once it is running, it is
ordinary Python in your process with all of your privileges. This is not a sandbox
and [says so](../README.md#this-is-not-a-sandbox).

**A plugin declares `read` and then deletes my files. What did preflight do?**
It enforced the declaration, which is all it claims to do. The bundled `impostor`
example exists to demonstrate exactly this hole: run `preflight demo` and find the
`impostor` row. It is caught, but only *after* its code ran, and only because it
contradicted its own manifest — a plugin that simply never mentions what it does
would not be caught at all.

**Why does `check` say a package is fine when it obviously isn't?**
Because `check` reads paperwork and never executes anything. "Paperwork is
consistent" is a statement about the manifest, and the output says so in as many
words.

**Can I keep the manifest somewhere other than `manifest.json`?**
No. The filename is fixed. If the package already has a `manifest.json` for another
system, the two cannot coexist in that folder.

**Do I need `preflight create` at all?**
No. It writes a starter file so you do not have to remember the required fields.
Hand-writing the JSON is equally valid.

**Can I use preflight to check a package before I download it?**
No — see [section 1](#1-what-you-are-about-to-build). It reads a directory on your
disk, and it reads declarations rather than code.

**Something else went wrong.**
Every check preflight makes is listed in order, each naming the test that proves it,
in [What it checks, in order](#14-what-it-checks-in-order--and-the-test-for-each).
If the behaviour you are seeing is not one of those rows, it is a bug — please open
an issue with the report `print(result)` produced.

---

## 9. Command-line reference

Section 6 is the short version: write a manifest, check it. This section is every
command and every message, for when you need the detail.

None of it protects a running application. This is you at a terminal, deciding
whether to let something near the gate at all, and writing down the terms if you do.

### 9.1 `preflight check`

`preflight check` reads a package's manifest and lists everything it claims the right to do. **It imports nothing** — not the plugin, not `importlib`, not even `find_spec`. The entrypoint is resolved by path arithmetic against the folder on disk, so there is no code path through this command that can cause the inspected package to execute. `tests/test_inspect.py` proves it with a tripwire, on a package that was genuinely importable at the time.

The one question path arithmetic cannot answer is whether the interpreter *already owns* the name your folder is using — a folder called `time` or `json` sits right there on disk and resolves perfectly, while no host can ever reach it. `check` settles that by reading `sys.builtin_module_names` and `sys.stdlib_module_names`, which is a lookup rather than an import, and refuses the package. See §7.2 for what the two cases print and why they are worded differently.

It also opens the entrypoint's own source file, once, to answer the other half of the entrypoint string: **is the `:attribute` actually defined there?** It is read with `ast.parse`, which builds a syntax tree and evaluates none of it — reading a file is not running it — and a name bound anywhere at module level counts, including one bound inside an `if` or by an `import`. Where the tree cannot answer, because the module defines `__getattr__` or does `from x import *`, `check` stays quiet rather than guess: a false `1` is the failure that stops people believing the exit code.

That refusal is reported apart from all the others, and the heading says why:

```
  1 reason a host would refuse this AFTER importing it:
    X entrypoint attribute 'create_plugin' is not defined in
      __init__.py. A host imports 'notepad', asks for 'create_plugin',
      and refuses the package when it is not there -- by which time
      the package's code has run. Define it in that file, or shorten
      the entrypoint to 'notepad' to have preflight adapt the module
      using this manifest.

  This package would be refused, and not before it had run --
  the reason above is one only an import can discover.
```

Every other reason `check` prints is one a host reaches with the package still inert on disk. This one is not, and that difference is the subject of the whole project — so it gets its own list rather than being filed under "before importing it". Both mean exit `1`. Only one of them means nothing happened.

What `check` still cannot tell you: whether the object that attribute yields satisfies the `Plugin` protocol, and whether the manifest it reports matches the one in the file. Those are checks 16 and 17, they need an object, and there is no object until something has been imported. Only the gate reaches them.

```
preflight check ./weather
```

```
preflight check | weather\ | nothing was executed

  manifest      valid
  package id    acme.weather
  plugin        Weather 2.1.0  (id: weather)
  tier          public, stable ring
  entrypoint    weather.plugin:create_plugin
                -> weather\plugin.py  (inside this folder)
  permissions   network.outbound

  declares 3 tools
      weather.today       read         reads data
    ! weather.subscribe   financial    can spend money
    ! weather.wipe_cache  destructive  deletes things

  Paperwork is consistent. preflight did not run this code and cannot
  tell you whether it does what it says.
```

The `!` marks every tool declaring something beyond a plain read. **These are claims the package makes about itself**, printed so you can decide whether a weather widget has any business being able to spend money. preflight has not read the code and cannot confirm or contradict any of it.

`check` exits `0` when every package would be accepted, `1` when any would be refused, and `2` on a bad path — so it works in a script without anyone reading the output.

### 9.2 `--refuse`, which is your rule and not preflight's

By default `check` reports and does not judge: a package declaring a tool that deletes things is *shown to you*, marked `!`, and left for you to decide about. `--refuse` is how you make that decision once and let the exit code carry it:

```
preflight check ./janitor --refuse destructive
```

<!-- transcript: preflight check examples/plugins/janitor --refuse destructive | setup=repo -->
```
preflight check | janitor\ | nothing was executed

  manifest      valid
  package id    example.janitor
  plugin        Janitor 1.0.0  (id: janitor)
  tier          public, stable ring
  entrypoint    janitor.plugin:create_plugin
                -> janitor\plugin.py  (inside this folder)

  declares 1 tool
    X janitor.purge_cache  destructive  deletes things

  1 tool declares a risk you refused: janitor.purge_cache (destructive)
  A host running Policy(refuse_tool_risks={ToolRisk.DESTRUCTIVE}) would
  refuse this package before importing it.

  Paperwork is consistent, and this package would still be refused --
  by your rule, not by preflight's. Its code would never be imported.
```

Exit `1`, on a package with nothing wrong with it. That is the intended result: the paperwork is in order and you said no anyway.

The flag takes a comma-separated list and is repeatable (`--refuse destructive,financial` and `--refuse destructive --refuse financial` are the same request). An unrecognised risk name is an error, not a silent no-op. Valid names are the [tool risk levels](#101-tool-risk-levels).

To stop retyping it on every command, save it: [`preflight settings`](#12-saving-your-settings). A saved rule applies to `check` and `demo` automatically, and passing `--refuse` **replaces** it for that one run rather than adding to it — so the flag can loosen as well as tighten.

**Note the line naming `Policy(...)`.** It is there because this command decides nothing that lasts. Run it in a pre-commit hook and it will stop a package entering your repository; it will not stop one loading at runtime, because it is not running then. The same rule enforced by the gate is [`Policy(refuse_tool_risks=...)`](../README.md#policy), and that is where it takes effect.

### 9.3 When there is no manifest

This is the common case for something you just downloaded:

<!-- transcript: preflight check random-repo | setup=empty_repo -->
```
preflight check | random-repo\ | nothing was executed

  no manifest.json found

  This package makes no declarations preflight can check, so preflight
  can tell you nothing about it. That is not a verdict on the package;
  it is the absence of one.

  To adopt it anyway, write down what you will permit it to do:
      preflight create <where>/random-repo
```

`preflight create` writes a manifest skeleton so you can adopt an unmanaged package on your own terms. Be clear about what it does and does not do: it records **what you permit**, and it does not read the package's code to find out what the package wants. The generated `tools` list is empty, which means the package may expose none until you add them yourself.

```
preflight create ./weather
preflight check ./weather      # now there is something to check
```

It refuses to overwrite an existing manifest without `--force`, and it refuses outright when the folder name is not a valid Python identifier — `import weather-tool` is a syntax error, no manifest can fix that, and writing one anyway would produce a file that only looks like progress.

### 9.4 When the manifest belongs to something else

`manifest.json` is a popular filename. Browser extensions use it, Figma plugins use it, web apps use it, and none of those are preflight's. Pointing `check` at one of them is a reasonable thing to do — it is often the first thing anyone does — so it gets its own answer rather than a schema error:

```
preflight check | design_linter\ | nothing was executed

  manifest      not preflight's

  This is a manifest.json, but not one of preflight's. It has none of
  the fields preflight requires (package_id, visibility, release_ring,
  entrypoint, plugin), and 13 that preflight does not recognise.

  Plenty of systems keep a file by that name, and preflight cannot
  read theirs -- it would have to guess what any of it permits. A
  preflight manifest is written by whoever sets the terms for
  loading: the package's author, when your host requires one, or
  you, when you adopt something that never heard of preflight.

  Writing yours means taking that filename:
      preflight create design_linter --force

  That replaces the file above. Move theirs aside first if the
  tool it belongs to still needs it.
```

Note what this does **not** say. It does not call the file invalid, because there is nothing wrong with it — a Figma manifest is a correct Figma manifest, and preflight has no standing to grade it. The distinction is drawn on evidence: a file carrying none of the fields preflight requires was written for something else, and a file carrying some of them was written for preflight and has a mistake in it. The second gets the mistake named, field by field:

```
  manifest      INVALID

  2 problems with this manifest:
    entrypoint           Field required
    plugin.tools.0.risk  Input should be 'read', 'write', 'destructive', ...
```

### 9.5 `preflight demo`

Loads the five bundled example plugins and refuses three of them, so you can see the refusals rather than read about them:

```
preflight demo
```

The output is in [section 11](#11-worked-examples). Run it again with a rule attached and a fourth plugin is refused:

```
preflight demo --refuse destructive
```

<!-- transcript: preflight demo --refuse destructive | setup=repo -->
```
  [greeter] top-level plugin code is executing
  [impostor] top-level plugin code is executing

preflight | plugins\ | 5 packages found

  LOADED   greeter     Greeter 1.0.0 - 1 tool
  REFUSED  trespasser  never imported
                       entrypoint module 'json' resolves to '<your python's stdlib>/json/__init__.py',
                       which is outside the trusted plugin root '.../examples/plugins'
  REFUSED  collider    never imported
                       tool name collision: 'greeter.hello' is already owned by 'greeter'
  REFUSED  impostor    imported, then rejected
                       runtime manifest for 'example.impostor' does not match its validated package manifest
                       tools -- undeclared in the manifest: impostor.purge_all_records
  REFUSED  janitor     never imported
                       package 'example.janitor' declares tool 'janitor.purge_cache' with risk 'destructive', which this host refuses

  1 loaded, 4 refused -- 3 of the 4 stopped before any of their code ran

  The 2 lines above reading `top-level plugin code is executing` are
  tripwires: the first statement in a plugin package. 3 of the 4 refused
  plugins never printed one, because they never got an import.

  Two of those refusals are worth comparing. janitor declared its
  destructive tool in its manifest, so --refuse stopped it while it
  was still inert on disk. impostor declares two read-only tools and
  produces a destructive third one only once loaded, where no
  declaration-based gate can see it -- it was caught afterwards, by
  comparing what it reported against what it had declared.

  preflight enforces declarations. It does not detect concealment.
```

The command makes that comparison itself, in its last paragraph, because it is the one thing about this output a reader has to leave with. `janitor` is a plugin with nothing wrong with it, refused for being honest about something you said you did not want — and refused while still inert on disk, so its tripwire never fires. `impostor` is the comparison: it declares two read-only tools and produces a destructive third one only once loaded, so `--refuse` never saw it. It is caught anyway, but afterwards, by comparing what it reported against what it declared.

**preflight enforces declarations. It does not detect concealment.** Those two rows are the shortest statement of that difference the project can make.

### 9.6 `preflight try`

`demo` is somebody else's plugins failing in ways they chose. `try` gives you your own to break:

```
preflight try weather-sandbox
cd weather-sandbox
python host.py
```

<!-- transcript: preflight try weather-sandbox -->
```
wrote .../weather-sandbox
      host.py                          the gate, 12 lines
      break.py                         the three exercises below
      plugins/weather/__init__.py      empty, and load-bearing
      plugins/weather/plugin.py        the plugin
      plugins/weather/manifest.json    what it is permitted to do

  This one loads. Nothing is wrong with it, which is the least
  interesting state it can be in.

  Run it:
      cd <where>/weather-sandbox
      python host.py

  Then break it, three times. Read the refusal before you read the fix.

  1. delete the __init__.py that makes it a package
       python break.py 1
       python host.py
       python break.py 1 --undo

  2. misspell the entrypoint in manifest.json
       python break.py 2
       python host.py
       python break.py 2 --undo

  3. bump module_version in plugin.py only, not in manifest.json
       python break.py 3
       python host.py
       python break.py 3 --undo

  The first two are refused from the manifest alone -- the plugin's
  code never runs. The third is caught after importing it, and the
  report tells you which of the two happened.
```

<!-- transcript: python host.py | setup=try -->
```
preflight | plugins\ | 1 package found

  LOADED   weather  Weather 1.0.0 - 1 tool

  1 loaded, 0 refused

today: 18C and raining
```

It then prints three ways to break it. Each is a single command, and the same command on every shell and every OS — `break.py` is written into the sandbox beside `host.py`, so nothing here depends on whether you are in bash, PowerShell or cmd:

```
python break.py 1          # delete the __init__.py that makes it a package
python host.py             # read the refusal
python break.py 1 --undo   # put it back
```

Running a break prints what it changed, which is the part a shell one-liner leaves you to assume. Break 1 deletes `plugins/weather/__init__.py`; rerun the host:

<!-- transcript: python host.py | setup=try_no_init -->
```
preflight | plugins/ | 1 package found

  REFUSED  weather  never imported
                    entrypoint module 'weather' has no file on disk, so it cannot be shown to live inside the trusted plugin root '.../weather-sandbox/plugins'
                    that folder is on disk but has no __init__.py, so Python treats it as a namespace package and it resolves to no single file. Create an empty '.../weather-sandbox/plugins/weather/__init__.py'.

  0 loaded, 1 refused -- 1 of the 1 stopped before any of their code ran
```

Put it back, then bump `module_version` in `plugin.py` only, leaving `manifest.json` alone:

<!-- transcript: python host.py | setup=try_version_drift -->
```
preflight | plugins/ | 1 package found

  REFUSED  weather  imported, then rejected
                    runtime manifest for 'local.weather' does not match its validated package manifest
                    module_version: manifest says '1.0.0', plugin reports '2.0.0'

  0 loaded, 1 refused -- 0 of the 1 stopped before any of their code ran
```

Every break has an undo — `python break.py <n> --undo` — but a skipped one leaves the sandbox failing for a reason you are no longer looking for. `preflight try` on a folder it already wrote says so and offers `--force`, which rewrites all five files back to the loading state.

**`--force` resets a sandbox. There is no flag that overwrites your own work.** A folder holding files preflight did not write is refused whatever you pass, because writing `host.py` over somebody's `host.py` is the one irreversible thing this command could do, and a guarantee with an escape hatch on it is not one.

The generated `host.py` ends with `sys.exit(1 if result.refused else 0)`, which is worth copying for a different reason: a refusal is *data*, not an exception, so nothing inside `load_plugins` stops your program. What a refusal means is the host's decision and it differs — an editor carries on without the plugin, a build fails — but it has to be made somewhere, or a break is visible only to whoever is reading the screen.

`1 of the 1` against `0 of the 1` is the whole distinction the library is built around, on your own code, in about a minute. The second one's top-level code ran before anything caught it — which is the honest limit of a check that needs an object to interrogate.

This command writes plugin code, which `create` deliberately refuses to do. That is the difference between a sandbox and a real adoption: a manifest records what *you* permit, and preflight guessing at that would defeat the point. Do not build on what `try` writes.

### 9.7 `preflight settings`

Saves the `--refuse` rule so it need not be retyped, per project and per agent.

```
preflight settings                    # what is in force, and where each value came from
preflight settings --where            # the file paths, whether they exist or not
preflight settings refuse financial,write
preflight settings refuse --clear
preflight settings --user refuse financial
preflight settings --profile research-agent refuse financial,write,destructive
preflight settings --as-python        # the Policy(...) to paste into a host
```

`check` and `demo` also take `--profile NAME`.

This configures the commands you type and **not** a running host — `load_plugins` reads no file. [Section 12](#12-saving-your-settings) is the full account, including why discovery deliberately never looks inside the package being inspected.

---

## 10. The manifest format

One file, fully annotated. This is every field that exists.

```jsonc
{
  // ---- how the host should treat this package -------------------------
  "schema_version": "1.0",       // manifest format version; only "1.0" exists
  "package_id": "example.mail",  // canonical dotted id, unique per install;
                                 // this is what your allowlist names
  "core_api_version": "1.0",     // plugin ABI the package targets
  "visibility": "public",        // who it is FOR:  public | internal | restricted
  "release_ring": "stable",      // how READY it is: stable | beta | experimental
  "entrypoint": "mail.plugin:create_plugin",
                                 // "module:attribute". If the attribute is
                                 // callable it is called; the result is the
                                 // plugin, and it must report a manifest equal
                                 // to the "plugin" block below -- check 17.
                                 // A bare "mail.plugin", with no colon, waives
                                 // that one check: preflight imports the module
                                 // and adapts it using this file. See section 6.1.

  // ---- what the plugin says it is -------------------------------------
  "plugin": {
    "schema_version": "1.0",
    "plugin_id": "mail",              // unique among *loaded* plugins; the key
                                      // you pass to registry.get()
    "name": "Mail",                   // human-readable
    "module_version": "1.2.0",        // the plugin's own version
    "supported_platforms": ["windows", "macos"],
                                      // empty list = no platform restriction
    "tools": [
      {
        "name": "mail.search",        // globally unique across loaded plugins
        "risk": "read",               // see below
        "surface": "backend",         // backend | client
        "description": "Search the mailbox."
      }
    ],

    // ---- declared metadata: carried through, never enforced -----------
    "permissions": ["mail.read"],     // what the plugin says it needs
    "data_classes": ["email"],        // what kinds of data it touches
    "ui_contributions": [],           // surfaces it wants to render into
    "migrations": [],                 // schema migrations it ships
    "health": { "state": "unknown" }  // last reported health
  }
}
```

Only the `entrypoint` has two legal shapes, and the colon is what separates them. With one, the package states what it is and the gate checks that statement against this file. Without one, this file is the whole statement and there is nothing to check it against — which is the honest shape for a package that has never heard of preflight, and a waiver a reviewer can see, because it is in the file they are already reading. Everything else in this section applies identically either way.

**The registry gates on exactly three fields inside `plugin`:** `plugin_id`, `supported_platforms`, and `tools`. The rest — `permissions`, `data_classes`, `ui_contributions`, `migrations`, `health` — is metadata the *host* reads after a successful load. It is in the model so it is validated and type-checked rather than passed around as a loose dict, and it is documented here so nobody has to wonder why a load-gate carries a health field.

### 10.1 Tool risk levels

`read` · `write` · `destructive` · `financial` · `credential` · `security` · `public_posting` · `sensitive_disclosure`

A risk level answers "what does the worst case look like if this tool gets called." It exists so a host can require confirmation, apply a policy, or refuse a whole tier of tool without having to guess from the tool's name.

**preflight does not act on it.** Nothing in the registry reads `risk`. It is a declaration you can build a policy on top of, not a policy.

### 10.2 The plugin ABI

One member. That is the entire interface a plugin object must satisfy:

```python
@runtime_checkable
class Plugin(Protocol):
    @property
    def manifest(self) -> PluginManifest: ...
```

`runtime_checkable` makes `isinstance()` work here, but be precise about what that proves: it checks the attribute is *present*, not that it holds a `PluginManifest`. The real check is separate — the registry validates the reported manifest and requires it to equal the declared one.

### 10.3 Release tiers (optional)

**Skip this if you ship one build.** Nothing else needs it, and the defaults handle the single-tier case.

Some applications ship the same plugin folder to different audiences and need a plugin that is fine internally to stay out of the public build. That is two independent questions, so preflight keeps them as two fields:

| Field | Values | Answers |
|---|---|---|
| `visibility` | `public` · `internal` · `restricted` | who the plugin is **for** |
| `release_ring` | `stable` · `beta` · `experimental` | how **ready** it is |

A build then declares what it accepts, via `Policy(edition=...)`:

| Edition | Accepts visibility | Accepts ring |
|---|---|---|
| `public` *(default)* | `public` | `stable` |
| `internal` | `public`, `internal` | `stable`, `beta` |
| `development` | all | all — never ship this one |

```python
from preflight import Edition, Policy, load_plugins

result = load_plugins("plugins", allow=[...], policy=Policy(edition=Edition.INTERNAL))
```

Both are checked before the import, so a plugin from the wrong tier never runs. One cross-field rule is enforced on the manifest itself: a `restricted` plugin may not label itself `stable`, since `stable` is the ring public builds accept.

If none of this applies to you, mark everything `public` / `stable` and forget the fields exist.

---

## 11. Worked examples

`examples/` contains five plugins. Three of them do not deserve to load.

Every plugin package prints one line as the very first statement in its `__init__.py`. That turns the abstract claim into something you can *see*: the tripwires that appear in the output are exactly the plugins that got as far as being imported.

```
python examples/host.py        # or: preflight demo
```

<!-- transcript: python examples/host.py | setup=repo -->
```
  [greeter] top-level plugin code is executing
  [impostor] top-level plugin code is executing
  [janitor] top-level plugin code is executing

preflight | plugins\ | 5 packages found

  LOADED   greeter     Greeter 1.0.0 - 1 tool
  REFUSED  trespasser  never imported
                       entrypoint module 'json' resolves to '<your python's stdlib>/json/__init__.py',
                       which is outside the trusted plugin root '.../examples/plugins'
  REFUSED  collider    never imported
                       tool name collision: 'greeter.hello' is already owned by 'greeter'
  REFUSED  impostor    imported, then rejected
                       runtime manifest for 'example.impostor' does not match its validated package manifest
                       tools -- undeclared in the manifest: impostor.purge_all_records
  LOADED   janitor     Janitor 1.0.0 - 1 tool

  2 loaded, 3 refused -- 2 of the 3 stopped before any of their code ran

tool ownership is exclusive
  greeter.hello -> greeter
  impostor.read_profile -> None

calling a plugin that loaded
  Hello, world.
```

The three tripwires print before the report because they fire during loading, while the report is assembled from what happened. Three plugins printed one; two never got the chance.

*(Only the absolute paths are shortened above — they are wherever you cloned this and whichever Python you ran it with. `tests/test_examples.py` runs this same script in a fresh interpreter and pins every outcome, because a quoted output is a claim.)*

**`greeter`** — valid. Loads, registers its tool, and answers when called.

**`trespasser`** — a directory containing a manifest and *no Python at all*. Its manifest sits inside the trusted root and passes every check that reads the file: canonical `package_id`, well-formed entrypoint, an acceptable visibility and ring. The only thing wrong with it is where its entrypoint points. Shape is not location: a manifest is allowed to *name* any module, and whether that module may be imported is decided separately, by resolving it to a file before the import happens.

**`collider`** — a perfectly good plugin that claims a tool name `greeter` already owns. Nothing is wrong with its code, which is the point: **`[collider]` never appears in the output.** It was refused from its manifest file alone, while still sitting inert on disk.

**`janitor`** — the one nothing is wrong with. Its paperwork is faultless and it declares exactly one tool, honestly, at risk `destructive`. It loads here because `examples/host.py` passes no `Policy` and so accepts every declared risk. Run `preflight demo --refuse destructive` and the same package with the same manifest is refused while still inert on disk, and `[janitor]` disappears from the output. Nothing about the plugin changed; the host's rules did. That is the entire shape of the project in one example — preflight does not decide that deleting things is unacceptable, it enforces your decision that it is.

**`impostor`** — the honest one. Its manifest declares two read-only tools; the object it produces reports a third. Its manifest *file* is faultless, so it clears every pre-import check and gets imported — its tripwire fires. This is the one refusal that necessarily lands after the plugin's code has run, because the check compares the object's self-description to the file's, and there is no object to ask until the import has happened.

Be precise about what that last check is worth. preflight compares two *descriptions* of the plugin. It does not read the plugin's source, analyse its classes, or verify that a tool called `purge_all_records` does anything destructive — that name is a label chosen by whoever wrote the plugin. What the check buys you: a host builds its permission prompts, its tool list, and its UI from `registry.available()`, so without this a plugin could be approved on the strength of one manifest and then hand the host a different one. What it does not buy you: anything about behaviour. A plugin that describes itself accurately and then deletes your database registers without complaint.

---

## 12. Saving your settings

Everything in section 4 is a flag you retype. `--refuse financial,write` is the
rule you have already decided on, typed again on every command, and there is
nowhere to write down "in this project, I never accept financial tools."

`preflight settings` is that place.

```
preflight settings refuse financial,write
```

From then on, `preflight check` and `preflight demo` apply the rule without being
told. Nothing else changes.

### 12.1 Read this part before you use it

**A settings file configures the commands you type. It does not configure a
running host.**

That is not a limitation that got left in; it is the reason the feature is allowed
to exist. `load_plugins` reads no file, ever. A host states its policy in its own
source, where it is reviewable, diffable, and cannot be moved by anything that
ships in a plugin folder. If a JSON file could change what your application loads,
then getting that file rewritten would be the whole attack.

So every settings screen ends with the same two lines, and they mean exactly what
they say:

```
  This applies to the preflight commands you type. It does not apply to a
  running host -- see 'preflight settings --as-python'.
```

### 12.2 Seeing what is in force, and why

With no arguments, `settings` prints the effective values and where each one came
from — modelled on `git config --list --show-origin`, because *"why is this
refusing?"* is the only question anyone actually has.

```
preflight settings
```

```
preflight | settings

  refuse              financial, write  project  <root>\preflight.settings.json
  edition             public            default
  platform            windows           default  (the running OS)
  max_manifest_bytes  262144            default

  profiles  research-agent
  use one with: preflight check <path> --profile <name>

  This applies to the preflight commands you type. It does not apply to a
  running host -- see 'preflight settings --as-python'.
```

`preflight settings --where` prints both file paths whether they exist or not,
which is what you want when the answer is "it came from a file you forgot about."

### 12.3 Where the files live, and where they deliberately do not

Two places, both owned by you:

| Scope | Location | Set with |
|---|---|---|
| project | `preflight.settings.json` in your working directory, or the nearest ancestor of it, stopping at a `.git` boundary | `preflight settings refuse …` |
| user | `%APPDATA%\preflight\settings.json`, or `$XDG_CONFIG_HOME/preflight/settings.json` | `preflight settings --user refuse …` |

**The search climbs from your working directory and never from the package being
inspected.** This is the part worth understanding, because the alternative looks
harmless and is not: if `preflight check ./downloads/weather` consulted files above
`./downloads/weather`, then anyone who can get you to unpack a folder can ship a
`preflight.settings.json` beside it saying `"refuse": []` — and the gate would be
configured by the party it is judging.

There is a second placement, and it is the one worth understanding, because it
beats the first rule by exactly one directory. Unpacking an archive into
`downloads/` and inspecting what came out is the ordinary thing to do — and your
shell is very often sitting in `downloads/` at the time:

```
downloads/preflight.settings.json     <- "refuse": []   beside, not inside
downloads/evil/                       <- the package you are checking
```

That file is not *inside* the package, so the first rule waves it through, and it
is nearer than your real settings, so yours are never reached. **A settings file
may therefore only reach down onto a package beneath it from a directory that
looks deliberately made** — one containing `.git`, `.hg`, `pyproject.toml`, or an
explicit `.preflight-root`. An unpacked folder carrying a settings file and
nothing else does not qualify, and is ignored.

**Be exact about what that is worth.** Every one of those markers is a file or a
folder, and an archive can contain files. A package that ships its own
`pyproject.toml` beside its own settings file passes the check — at that point
every file in the tree was chosen by the same party, and no test of the filesystem
can tell you otherwise. This rule stops the realistic case; it is a filter, not a
lock. The only anchor that cannot be forged is your **user-scope** file, because it
lives somewhere nothing is ever unpacked into. `tests/test_settings.py` pins the
forged-marker case explicitly, so it is a known boundary rather than a surprise.

Either placement is ignored out loud, and the message names which one it was. A
file *inside* the directory you are inspecting:

```
preflight: ignoring <root>\downloads\evil\preflight.settings.json
           it is inside the folder being inspected, so it is in the hands of whatever put it there.
           preflight is not configured by the thing it is inspecting. Move it to
           your project root to have it apply.
```

And one *beside* it, in a directory with no sign of having been made by hand:

```
preflight: ignoring <root>\downloads\preflight.settings.json
           it sits above the folder being inspected, in a directory with no sign
           of having been set up by hand, so it is in the hands of whatever put it there.
           preflight is not configured by the thing it is inspecting. Move it to
           your project root to have it apply.
```

**Ignoring a file does not abandon the search** — your real project settings still
apply, from further up. This half matters as much as the first: if a rejected file
took the project scope down with it, then planting one would erase the rules you
wrote, and a rule silently downgraded to nothing is as good an outcome for an
attacker as one they chose. `tests/test_settings.py` proves each rule by reverting
it and confirming the tests fail without it.

**There is no `allow` key, and writing one is an error rather than a key that gets
quietly dropped.** The allowlist decides whether a package is imported at all. It
is required, has no wildcard, and lives in your host's source on purpose — a file
that could add package ids to it is precisely the attack the paragraph above exists
to prevent.

### 12.4 One profile per agent

"Per agent" means a named profile, kept in the same file. There is no second format
and no second discovery path.

```
preflight settings --profile research-agent refuse financial,write,destructive
preflight check ./some-plugin --profile research-agent
```

```json
{
  "version": 1,
  "refuse": ["financial", "write"],
  "profiles": {
    "research-agent": {
      "refuse": ["destructive", "financial", "write"]
    }
  }
}
```

### 12.5 Precedence

Lowest to highest. Later wins.

| # | Source |
|---|---|
| 1 | preflight's defaults (the strictest values available) |
| 2 | user scope |
| 3 | project scope |
| 4 | `--profile NAME` |
| 5 | `--refuse` on the command line |

**A flag replaces the saved value rather than adding to it.** Someone reaching for
`--refuse` at a prompt is usually trying to get *out* of what the file says, and an
override that can only ever tighten is not an override. Repeated `--refuse` flags
still union with each other — that part is unchanged. `--clear` removes a key
entirely, so the next layer down is heard again, rather than pinning an empty value
that would shadow it.

### 12.6 Turning it into a real gate

This is the command the rest of the section is for.

```
preflight settings --as-python
```

<!-- transcript: preflight settings --as-python | setup=saved_refuse -->
```python
from preflight import Policy, ToolRisk, load_plugins

result = load_plugins(
    "plugins",
    allow=["acme.weather"],  # required, and there is no wildcard
    policy=Policy(refuse_tool_risks={ToolRisk.FINANCIAL, ToolRisk.WRITE}),
)
```

Paste that into your host and the rule you have been testing at a terminal becomes
the rule that runs at every startup — by an explicit act you can see in a diff,
rather than by a file preflight reads behind your back. Fill in your own `allow`
list; it is the one thing a settings file will not write for you.

If your settings are all at their defaults, this prints no `Policy` at all and says
why: the defaults are the strictest values available, so passing none is the safest
thing you can do.

### 12.7 When something is wrong with the file

Every failure exits `2` — "you gave me something I cannot work with" — and never
`1`, which already means "would be refused" on `check` and must not come to mean
two things. Malformed JSON, an unknown risk name, an unrecognised key, a version
this build does not understand, and an unwritable path each get a sentence naming
the file and the problem, not a stack trace.

preflight refuses a settings file it cannot fully understand rather than ignoring
the parts it does not recognise — the same rule it applies to a manifest.

---

## 13. preflight inside an agent

Section 12 ends on a warning it is worth turning around and answering properly.
Settings configure the commands you type; they do not configure a running host. So
if preflight is the gate at your agent's startup, **how do you change its rules?**

The short answer: your agent reads its own configuration and builds a `Policy` from
it. preflight does not read a file for you, and this section is about why that is
the right division of labour rather than a missing feature.

### 13.1 The whole arc, once

Start to finish, the first time:

```
pip install preflight-gate

preflight try sandbox           # 1. a working host and plugin, to break on purpose
cd sandbox && python host.py

preflight check ./downloaded    # 2. read a package you did not write
preflight create ./downloaded   # 3. write down what you permit it to do

preflight settings refuse financial,write     # 4. save the rule you keep retyping
preflight settings --as-python                # 5. the line to paste into your host
```

Steps 1–3 are the terminal. Step 5 is the door between the terminal and your
program, and everything after it happens inside your agent, at every startup,
whether or not anyone is watching.

### 13.2 The gate at startup

```python
import sys
from pathlib import Path

from preflight import Policy, ToolRisk, load_plugins

PLUGINS = Path(__file__).resolve().parent / "plugins"
sys.path.insert(0, str(PLUGINS))  # preflight will not do this for you

result = load_plugins(
    PLUGINS,
    allow=["acme.weather", "acme.calendar"],
    policy=Policy(refuse_tool_risks={ToolRisk.FINANCIAL, ToolRisk.WRITE}),
)

for outcome in result.refused:
    log.warning("plugin refused: %s -- %s", outcome.folder, outcome.reason)

tools = [tool for plugin in result.plugins.values() for tool in plugin.manifest.tools]
```

Two things an agent should do with the result and often does not.

**Read `allow` as the real gate.** Discovery is a convenience for a loop you would
otherwise write yourself. A package sitting in the folder and missing from `allow`
is never imported, and that is the guarantee — not the absence of a scan.

**Log `outcome.code_ran`.** `outcome.stage` says `never imported` or `imported,
then rejected`, and the difference is the entire point of the library. An agent
that logs "plugin refused" without it has thrown away the only fact worth having:
whether the refusal cost the plugin nothing, or arrived after its code had already
run.

### 13.3 Changing the rules without editing code

A real deployment wants the policy to vary — stricter in production, looser on a
developer's laptop. Do that by reading **your own** configuration and constructing
the `Policy` yourself:

```python
import os

from preflight import Policy, ToolRisk, load_plugins

REFUSE = {
    "strict": {ToolRisk.FINANCIAL, ToolRisk.WRITE, ToolRisk.DESTRUCTIVE},
    "normal": {ToolRisk.FINANCIAL, ToolRisk.DESTRUCTIVE},
    "dev": set(),
}

profile = os.environ.get("AGENT_PLUGIN_POLICY", "strict")  # default is strictest
result = load_plugins(
    PLUGINS,
    allow=ALLOWED,
    policy=Policy(refuse_tool_risks=REFUSE[profile]),
)
```

preflight has no opinion about where that value comes from. An environment
variable, your agent's existing config file, a secrets manager, a database — all
fine. **What matters is one property, and it is the same property section 12.3 is
built around:**

> Whatever your host reads its policy from must be somewhere the plugins it is
> judging cannot write.

An environment variable set by your deploy system qualifies. Your application's own
config file, sitting outside the plugin directory, qualifies. A file *inside*
`plugins/`, or anywhere a plugin can reach at runtime, does not — and that is the
one arrangement preflight refuses to make convenient for you, because a gate whose
rules live on the wrong side of the boundary is not a gate.

Note the default in that snippet. If the environment variable is missing or the
lookup fails, the code above lands on `strict`, not `dev`. Fail closed; a
misconfiguration should not silently widen what may load.

### 13.4 Keeping the two in step

The command line and the host are now two statements of one rule, and they can
drift. Two habits keep them honest:

```
preflight settings --as-python        # regenerate the Policy line, paste, diff it
preflight check ./plugins --profile production
```

`check` takes **one** path. Point it at the directory holding your plugin packages
and it reports on each one in turn — a shell glob would hand it several arguments
and it would exit `2` rather than checking anything.

Give the profile the name of the deployment it mirrors, so `--profile production`
and your production `Policy` are visibly the same rule asked in two places. And put
`preflight check --refuse …` in CI: it exits `1` on a package your host would turn
away, which catches a plugin that would have been refused at startup — at review
time instead, where somebody is looking.

### 13.5 What this does not give you

Worth restating here, because an agent is exactly the context where it gets
forgotten. Once a plugin is imported it is ordinary Python with the full run of
your process. preflight has no power after the import: it is not a sandbox, it does
not read plugin code, and it cannot tell you whether a package does what its
manifest claims. What it gives you is the ability to say no *before* the import —
and, in `outcome.code_ran`, an honest record of whether it managed to.

---

## 14. What it checks, in order — and the test for each

Every row names the test that proves it. If you doubt a row, run that test; if a row
had no test, it would not be in this table.

| # | Check | Test |
|---|---|---|
| 1 | The manifest file is inside `trusted_root` | `test_manifest_file_is_confined_and_validated_before_import` |
| 2 | The manifest is under 256 KiB — refused before it is even parsed | `test_an_oversized_manifest_is_refused_before_it_is_even_parsed` |
| 3 | It is valid JSON and validates against a **closed** schema (an unknown field is a refusal, not a shrug) | `test_plugin_package_manifest_is_closed_and_has_a_strict_entrypoint` |
| 4 | The manifest is re-validated at registration, so a model mutated in memory cannot slip through | `test_registry_revalidates_mutated_manifests_before_loading` |
| 5 | `package_id` is on the build's explicit allowlist | `test_public_registry_requires_an_explicit_build_allowlist_before_loading` |
| 5a | A package found on disk but absent from `allow` is never imported — discovery does not imply loading | `test_a_package_on_disk_but_not_in_allow_is_never_imported`, `test_an_empty_allowlist_loads_nothing_that_is_sitting_there` |
| 5b | Load order follows `allow`, so tool-name precedence is the host's decision and not the filesystem's | `test_load_order_follows_the_allowlist_not_the_filesystem` |
| 5c | A tool risk the host refuses stops the package before the import | `test_a_refused_tool_risk_stops_the_plugin_before_it_is_imported` |
| 6 | The plugin supports the platform this build is running on | `test_a_plugin_that_does_not_support_the_host_platform_is_refused_before_loading` |
| 7 | `visibility` and `release_ring` are both accepted by this build's edition | `test_public_registry_rejects_non_public_modules_before_loading` |
| 8 | A restricted plugin cannot label itself with the stable ring | `test_plugin_package_manifest_is_closed_and_has_a_strict_entrypoint` |
| 9 | `plugin_id` is not already registered | `test_a_second_package_claiming_a_registered_plugin_id_is_refused_before_loading` |
| 10 | No duplicate tool names inside one package | `test_duplicate_declared_tool_names_are_rejected_before_loading` |
| 11 | No tool name already owned by a loaded plugin | `test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions` |
| 12 | The entrypoint module — **and every parent package on the way to it** — resolves to a file inside `trusted_root`, located without being executed | `test_an_entrypoint_outside_the_trusted_root_never_executes`, `test_a_dotted_entrypoint_cannot_execute_an_out_of_tree_parent_package` |
| 13 | A module with no file on disk (built-in, frozen, namespace package) is refused rather than trusted | `test_an_entrypoint_naming_a_builtin_module_is_refused`, `test_an_entrypoint_naming_a_standard_library_module_is_refused` |
| 13n | *Not a check.* Four unrelated mistakes reach row 13, so the refusal names which one, read off the filesystem after the decision is made. It cannot widen what loads. | `test_a_folder_without_an_init_is_told_it_is_a_folder_without_an_init`, `test_a_name_that_is_not_in_the_root_at_all_points_at_the_manifest`, `test_a_root_that_is_not_on_sys_path_says_so_rather_than_blaming_the_plugin`, `test_a_plugin_folder_named_after_a_builtin_module_is_told_it_collides` |
| 13a | Resolving a *dotted* entrypoint imports its parent package — `find_spec("a.b")` runs `a` — so the parent clears the boundary before it is resolved, and a package whose `__init__` runs and then fails is reported as having run | `test_a_dotted_entrypoint_cannot_execute_an_out_of_tree_parent_package`, `test_a_package_that_ran_and_then_failed_is_not_reported_as_inert`, `test_a_top_level_entrypoint_is_still_announced_only_at_the_import` |
| 14 | The confinement check is *what* stops the import — not something else that would have refused anyway | `test_the_confinement_check_is_what_stops_the_out_of_tree_import` |
| — | **Everything above this line is decided from files on disk**, and no file executes before it has cleared the boundary. The one thing that does execute up here is a dotted entrypoint's parent package, at row 13a — and when it does, `code_ran` says so. | |
| 15 | After importing, the module's real `__file__` is re-checked against `trusted_root` | `test_a_module_whose_file_changes_after_resolution_is_still_refused` |
| 16 | The loaded object actually satisfies the `Plugin` protocol | `test_an_entrypoint_returning_something_other_than_a_plugin_is_refused` |
| 17 | The manifest the object reports equals the manifest its file declared | `test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions` |
| 17w | A **bare entrypoint waives 16 and 17** — the package makes no statement, so there is nothing to check this file against. It waives nothing else: the module is still confined to the trusted root, and the tools the host advertises still come from the file rather than the object | `test_a_bare_entrypoint_is_still_confined_to_the_trusted_root`, `test_the_tool_surface_comes_from_the_file_either_way`, `test_a_colon_entrypoint_is_still_checked_against_what_the_package_reports` |
| 17r | The waiver is reported, so `LOADED` does not quietly mean two strengths of the same word | `test_the_report_says_a_bare_entrypoint_was_adapted`, `test_the_adapted_module_is_not_modified_by_being_adapted` |
| 18 | On any refusal the registry is unmodified — no partial registration | asserted in every rejection test above (`registry.available() == ()`) |
| 19 | Everything handed back out is a deep copy; mutating it cannot reach the registry | `test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions` |
| 20 | `preflight check` reports on a package without importing it — including one that was importable at the time | `test_inspecting_a_package_never_imports_it`, `test_check_never_imports_the_package_it_is_pointed_at` |
| 21 | `preflight check` reaches the same verdict as the gate, in the same words — platform and release ring included, not only declared risk | `test_check_refuses_what_the_gate_refuses_and_says_the_same_thing`, `test_check_exits_non_zero_on_a_risk_the_caller_refused` |
| 21a | A plugin folder named after a module the interpreter already owns is refused by `check` too — verbatim in the gate's words for a built-in, and in `check`'s own words for a pure-Python stdlib name, where the gate's sentence quotes a path only `find_spec` could supply | `test_a_folder_named_after_a_builtin_is_refused_in_the_gates_exact_words`, `test_a_folder_named_after_a_stdlib_module_is_refused_but_not_word_for_word`, `test_a_name_that_only_looks_like_a_stdlib_module_is_still_accepted` |
| 21b | Deciding a name is unreachable is still a lookup in two frozensets, so `check` keeps its one hard guarantee | `test_calling_a_package_unreachable_still_does_not_import_it` |
| 21c | `check` verifies the entrypoint's `:attribute` half as well as its module, and reports it apart from the rest because a host reaches it only *after* importing | `test_a_package_with_no_create_plugin_is_refused_by_both`, `test_a_missing_attribute_is_reported_as_costing_the_package_its_import` |
| 21d | That check reads the syntax tree, so a name bound behind an `if` counts, one bound inside a function does not, and a module that can invent names gets the benefit of the doubt | `test_an_attribute_defined_behind_a_conditional_is_still_found`, `test_an_attribute_only_a_function_body_defines_is_not_found`, `test_a_module_that_can_invent_names_is_given_the_benefit_of_the_doubt` |
| 21e | Parsing the package's source is not running it | `test_looking_for_the_attribute_does_not_import_the_package` |
| 22 | Refusing a risk at the gate stops the plugin with its code still inert, and cannot reach a risk that was never declared | `test_refusing_a_declared_risk_stops_the_janitor_before_it_is_imported`, `test_refusing_a_declared_risk_cannot_reach_a_risk_that_was_never_declared` |
| 23 | A `manifest.json` belonging to another system is reported as such, not as an invalid preflight manifest | `test_another_systems_manifest_is_reported_as_foreign_rather_than_invalid`, `test_a_preflight_manifest_with_a_mistake_in_it_is_invalid_and_not_foreign` |

Rows 1–14 are the point of the project. Rows 15–17 are what is left over — checks
that *cannot* be made before the import, because they are about an object, and there
is no object until something has been imported.

`preflight demo` runs five bundled plugins through this table and refuses three of
them. Each one prints a tripwire as the first statement of its `__init__.py`, so the
plugins that appear in the output are exactly the ones that got as far as being
imported — and the ones that do not appear are the rows above the line, working.
Plugin by plugin: [Worked examples](#11-worked-examples).

### 14.1 About row 14

A security test that passes both with and without the fix proves nothing.
`test_the_confinement_check_is_what_stops_the_out_of_tree_import` runs one scenario
twice through the same harness and changes exactly one thing — which importer the
registry is handed. The second importer is a copy of what this loader did *before*
the confinement check existed, kept in the test file as a control condition.

The interesting result is not that the confined importer refuses the plugin. It is
*when* the unconfined one does: it refuses it too, on a later and unrelated ground,
having already run the plugin's top-level code. **Raising an exception is not the
same as failing closed**, and that test is what tells the two apart.

### 14.2 Row 21, and the gap that was there until 0.6.0

`preflight check` used to judge the paperwork and the declared risks, and nothing
else. A package the gate would refuse for its platform or its release ring printed
"Paperwork is consistent" and exited `0`.

That mattered because of [§13.4](#134-keeping-the-two-in-step), which recommends the
command for CI precisely so a plugin that would be refused at startup is caught at
review time instead. For two of the four preload checks it was answering a smaller
question than the one being asked of it.

Both paths now call one function — `preflight.registry.preload_refusals` — and
`tests/test_check_matches_the_gate.py` pins the consequence rather than the
refactor: the same package, judged twice, must come back with the same answer in the
same words.

---

## 15. Why it exists

This was extracted from a personal AI assistant — a desktop application with several
plugin packages and multiple build tiers, where a plugin in the wrong tier reaching a
shipped build was a real failure mode rather than a hypothetical one. The loader had
to answer "may this load here?" from the manifest alone, because by the time it could
ask the plugin, the answer would not have mattered.

The extraction found a hole in the original, and the history keeps it: the first
three commits land the loader with the bug, and the fourth closes it. Before the fix
the manifest *file* was confined to the trusted root but the entrypoint *string*
inside it was confined to nothing, so a manifest in the right place could name any
importable module on `sys.path`. It is `e0d2f8a`, and
`tests/test_negative_control.py` measures the difference rather than asserting it.

The reason this generalises beyond one desktop app is that dynamic plugin loading is
currently exploding in agent tooling — MCP servers, agent skills, tool packs — and
very little of it is gated. The manifest here already speaks that vocabulary (tools,
risk levels, permissions) because that is what the original application needed it to
describe. To be clear about the scope of that claim: this is a plugin trust boundary
that happens to suit agent tooling, not an agent framework.

---

## 16. Everything `import preflight` gives you

Most hosts need four names. The rest is here so that `dir(preflight)` stops being
the reference, and so that "internal, don't build on this" is written down rather
than left to be guessed at.

### The four you need

| Name | What it is |
|---|---|
| `load_plugins(directory, allow=..., policy=...)` | The gate. Everything else on this page is in service of this call. |
| `Policy` | The host's rules, stated in the host's own source. Never read from disk — see §12. |
| `ToolRisk` | The risk vocabulary, for `Policy(refuse_tool_risks=...)`. |
| `LoadReport` | What `load_plugins` returns. `.plugins`, `.get(id)`, `.loaded`, `.refused`, `.text()` — §5. |

### The manifest model

These mirror `manifest.json` field for field. You need `PluginManifest` only if
your package reports its own manifest — the `:attribute` form of the entrypoint
(§6.1); a package preflight adapts never touches any of them.

| Name | What it is |
|---|---|
| `PluginManifest` | The `plugin` block: what one plugin says it is. What your `create_plugin` must return on `.manifest`. |
| `PluginPackageManifest` | The whole file, `plugin` block included. |
| `Plugin` | The entire plugin ABI: an object with a `manifest` property. Nothing else. |
| `Tool`, `ToolSurface` | One declared tool, and whether it is a backend or client surface. |
| `Visibility`, `ReleaseRing`, `Platform` | The tier and platform vocabularies. |
| `UIContribution`, `Migration`, `Health`, `HealthState` | Declared metadata: validated, carried through, never enforced. Read them after a load if your host has a use for them. |
| `MANIFEST_NAME` | `"manifest.json"`. The filename is fixed; this is here so you do not hardcode it. |

### The parts of the gate, for a host that needs them

| Name | What it is |
|---|---|
| `PluginRegistry` | What `load_plugins` drives. Use it directly to load manifests one at a time, or to keep a registry across several calls. |
| `PluginRejected` | The refusal. `load_plugins` catches these and reports them; a direct `PluginRegistry` caller sees them raised. |
| `RegisteredPlugin` | One loaded plugin: its package manifest, its instance, and where it came from. |
| `Edition` | Which tiers a build accepts. Prefer `Policy(edition=...)`. |
| `public_build`, `internal_build`, `development_build` | Pre-configured registries, one per edition. |
| `Outcome` | One package's result inside a `LoadReport`. `.code_ran` is the field worth knowing. |

### What `preflight check` runs

Public because the command is a thin wrapper over them, and a host that wants to
build its own review tool should not have to reimplement them.

| Name | What it is |
|---|---|
| `inspect_package(folder)` | Read one package. Imports nothing. Returns an `Inspection`. |
| `inspect_directory(directory)` | The same for a folder of packages, or a single one. |
| `Inspection` | The result. `.refusals()` for reasons a host would refuse before importing, `.late_refusals()` for the one it can only reach after — §9.1. |
| `format_inspection(inspection, ...)` | The report `check` prints, as a string. |

### Not part of the API

`preflight.load`, `preflight.registry`, `preflight.manifest`, `preflight.inspect`
are submodules that appear in `dir(preflight)` because the package imports from
them. Import the names above from `preflight` itself; anything reachable only by
reaching into a submodule is internal and may move without notice.
