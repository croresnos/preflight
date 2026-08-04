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
python -m pip install "preflight @ git+https://github.com/croresnos/preflight"
```

Python 3.11 or newer. The only dependency is pydantic.

Check it landed:

```
preflight --version
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

`try` writes plugin code. `create` (section 5) deliberately does not — a manifest
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
format](../README.md#the-manifest-format).

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
print(result.plugins["greeter"].hello("world"))   # KeyError if greeter was refused
```

In anything real, ask first:

```python
greeter = result.plugins.get("greeter")
if greeter is None:
    ...        # log result.refused and carry on, or exit, or fall back
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
levels](../README.md#tool-risk-levels).

Everything is a keyword argument and there is no configuration file, because a
settings file living next to your plugins would be a file a plugin could write. The
defaults are the strictest values available, so a call that passes no `Policy` at
all is the safest call you can make. Other settings: [Settings](../README.md#settings).

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
result.plugins          # {plugin_id: instance} -- only what loaded
result.loaded           # the outcomes that loaded
result.refused          # the outcomes that did not
for outcome in result.refused:
    outcome.folder      # the directory name
    outcome.reason      # the refusal message
    outcome.code_ran    # True if the plugin's code executed first
    outcome.stage       # "never imported" | "imported, then rejected"
```

---

## 6. Adopting a package you did not write

Sometimes you decide to gate a package that has never heard of preflight. Then you
write the manifest, because you are the one setting the terms:

```
preflight create plugins/weather
```

```
wrote <root>\plugins\weather\manifest.json

  This manifest records what you PERMIT this package to do. preflight
  did not read its code and has not checked whether the two agree.
  An empty `tools` list means it may expose none.

  Next:
      preflight check <root>\plugins\weather
```

It writes a minimal manifest with `tools: []` — permitting nothing — and guesses the
entrypoint from the folder name. Open it and write down what you actually intend to
allow. `preflight check` then reads it back without importing anything:

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

**Neither command protects a running application.** Writing a manifest is a decision
you record; enforcing it is `load_plugins`, in your host, at startup. Full CLI
reference including `--refuse`: [Adopting a package you did not
write](../README.md#adopting-a-package-you-did-not-write).

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
<td>Your plugin folder is named after something already importable — a stdlib module
(<code>time</code>, <code>json</code>, <code>types</code>) or an installed package.
Your paperwork is fine and no amount of fixing it will help; the name is taken
before the trusted root is ever consulted. Rename the folder and the
<code>entrypoint</code> together.</td></tr>
<tr><td><code>entrypoint module '&lt;name&gt;' resolves to '&lt;path&gt;', which is outside the trusted plugin root '&lt;root&gt;'</code></td>
<td>The entrypoint points at something real but out of bounds — a standard library
module, or an installed package. This is the check the whole project exists for. It
is not a configuration problem; do not widen the root to make it go away.</td></tr>
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
<a href="../README.md#release-tiers-optional">Release tiers</a>.</td></tr>
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
<tr><td><code>runtime manifest for '&lt;id&gt;' does not match its validated package manifest</code></td>
<td>The <code>plugin</code> block in <code>manifest.json</code> and the one in the
running object are not equal. Nearly always drift — someone bumped
<code>module_version</code> or added a tool in one place only. Diff the two.
This check is also the one that catches a plugin lying about what it exposes, which
is why the two copies exist.</td></tr>
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
in [What it checks, in order](../README.md#what-it-checks-in-order--and-the-test-for-each).
If the behaviour you are seeing is not one of those rows, it is a bug — please open
an issue with the report `print(result)` produced.
