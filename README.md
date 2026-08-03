# preflight

**Decide whether a plugin is allowed to load by reading its manifest file — before a single line of the plugin's code runs.**

Importing a Python module runs it. So a plugin loader that imports a plugin in order to find out what it is has already let it do whatever it was going to do. The check happens after the fact.

preflight moves every decision in front of the import. It reads a JSON manifest, validates it, applies your build's policy, and checks for name collisions — all against inert text — and only then imports anything.

```
python -m pip install "preflight @ git+https://github.com/croresnos/preflight"
```

There are two ways to use it.

**On the command line**, to read a package's paperwork before you install it. This imports nothing, so it is safe to point at code you have not read:

```
preflight check ./some-plugin
```

**As a library**, to gate plugins at runtime inside your own application:

```python
from preflight import load_plugins

result = load_plugins("plugins", allow=["example.greeter"])
print(result)
greeter = result.plugins["greeter"]
```

### What preflight is not

Read this before the rest, because the two halves above are easy to over-read.

- **It is not a scanner.** `preflight check` never reads the package's *code*. It reads the package's *declaration about itself* and tells you whether that declaration is coherent. It cannot detect malware, and it has no opinion on whether a package does what it claims.
- **It is not a sandbox.** Once a plugin is imported it is ordinary Python with the full run of your process. preflight decides *whether* to import and has no power after that.
- **It only works where there is a manifest.** That is not a gap waiting to be filled — it is the trade. The description has to live outside the code, so someone has to write it: the plugin author, because your application requires it, or you, with `preflight init`, when you adopt something that never heard of preflight. Either way a manifest records a judgement, and preflight enforces that judgement rather than forming one of its own.

### Who this is for

You are writing a program that loads plugins — yours or other people's — and you want the decision about each one made before it runs.

In that position you are not hoping a manifest exists. **You require one, and that is ordinary.** Chrome extensions do not load without `manifest.json`; VS Code extensions do not load without a `contributes` block; Obsidian plugins have a `manifest.json` too. Every plugin system worth the name makes the plugin declare itself in a file the host can read first, because the alternative is asking the code, and asking the code means running it. preflight gives you that requirement, a schema for it, and a gate that enforces it — including the part almost everyone gets wrong, which is doing all of it before the import.

If what you want instead is to know whether something you downloaded is safe to install, preflight is the wrong tool and no amount of it will become the right one. That needs a scanner that reads code, and this is not one.

---

## The problem

Almost every plugin system in Python is some version of this:

```python
import importlib

module = importlib.import_module(plugin_name)   # <-- the plugin's code has now run
manifest = module.MANIFEST
if manifest["version"] not in SUPPORTED:        # <-- too late
    raise RuntimeError("unsupported plugin")
```

The `if` is guarding nothing. By the time it is evaluated, every statement at the left margin of `plugin_name` — and of every package on the way to it — has already executed. That includes anything the plugin's author put at import time, deliberately or otherwise.

This is not a mistake anyone made by being careless. It is the shape the language pushes you into: there is no "import but don't execute" in Python. If the only description of a plugin lives inside the plugin, you have to run the plugin to read it.

So preflight requires the description to live *outside* it.

## What preflight does instead

Every plugin ships a `manifest.json` next to its code. JSON is inert — parsing it cannot execute anything. The registry's whole job is to make its decisions from that file:

```
read the manifest file   (confined to a trusted directory, size-capped)
      ↓
validate it              (closed schema — unknown fields are rejected, not ignored)
      ↓
apply build policy       (allowlist, platform, visibility, release ring)
      ↓
check collisions         (duplicate plugin ids, duplicate and colliding tool names)
      ↓
resolve the entrypoint   (find_spec — locates the module's file without running it)
      ↓
─────────── only now is anything imported ───────────
      ↓
verify what loaded       (it must report the same manifest it declared)
```

Every step above the line reads a file on disk. If any of them refuses, the plugin's code never executed and the registry was not modified.

---

## Quickstart

Lay a plugin out like this. The manifest and the Python live together inside one trusted directory:

```
myapp/
├── host.py
└── plugins/                 <- the trusted root
    └── greeter/
        ├── __init__.py      <- required; see the FAQ
        ├── plugin.py
        └── manifest.json
```

`plugins/greeter/plugin.py`:

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

`plugins/greeter/manifest.json` — the same plugin block, plus how it should be treated:

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

print(result)                                    # the report, below
print(result.plugins["greeter"].hello("world"))  # Hello, world.
```

`print(result)` gives you this:

```
preflight | plugins\ | 1 package found

  LOADED   greeter  Greeter 1.0.0 - 1 tool

  1 loaded, 0 refused
```

Three things that are load-bearing and easy to miss:

- **`allow` is required and has no wildcard.** A package sitting in the folder but absent from `allow` is discovered, reported, and never imported. Discovery saves you the `for` loop; it is the allowlist, not the absence of a scan, that keeps an unexpected folder from loading.
- **The order of `allow` is the order things load,** and the first plugin to claim a tool name keeps it. That makes precedence something you wrote down rather than something the filesystem decided alphabetically.
- **The directory you pass is the security boundary.** Every manifest must be inside it and every entrypoint must resolve to a file inside it. If you point it at a directory anyone can write to, none of the rest of this matters.

### Reading the report

The middle column of a refusal is the part worth your attention:

```
  LOADED   greeter     Greeter 1.0.0 - 1 tool
  REFUSED  collider    never imported
                       tool name collision: 'greeter.hello' is already owned by 'greeter'
  REFUSED  impostor    imported, then rejected
                       runtime manifest for 'example.impostor' does not match its validated package manifest

  1 loaded, 2 refused -- 1 of the 2 stopped before any of their code ran
```

**`never imported`** means the plugin was refused while still inert on disk. Nothing of it ran. That is what preflight is for.

**`imported, then rejected`** means the check could only be made against a live object, so the plugin's import-time code executed before it was turned away. Refusing it kept it out of the registry; it did not keep it from running. Both outcomes appear in normal output because the difference between them is the honest measure of what preflight did for you — and `Outcome.code_ran` is recorded from the import itself, not guessed from which error came back.

### Settings

Everything is a keyword argument. There is no configuration file, and that is deliberate: a settings file living next to your plugins would be a file a plugin could write, which would turn your policy into something the untrusted side of the boundary controls.

The defaults are the strictest values available, so a call that passes no `Policy` at all is the safest call you can make:

```python
from preflight import Policy, ToolRisk, load_plugins

result = load_plugins(
    "plugins",
    allow=["example.greeter"],
    policy=Policy(
        refuse_tool_risks={ToolRisk.DESTRUCTIVE, ToolRisk.FINANCIAL},
        platform="linux",            # defaults to the OS you are running on
        max_manifest_bytes=64 * 1024,
    ),
)
```

`refuse_tool_risks` is the one place preflight acts on a declared risk level, and only because a host asked it to. It is checked before the import, so a package declaring a refused risk never runs. See [Release tiers](#release-tiers-optional) for `Policy(edition=...)`, which most hosts never need.

---

## Checking a package before you install it

`preflight check` reads a package's manifest and lists everything it claims the right to do. **It imports nothing** — not the plugin, not `importlib`, not even `find_spec`. The entrypoint is resolved by path arithmetic against the folder on disk, so there is no code path through this command that can cause the inspected package to execute. `tests/test_inspect.py` proves it with a tripwire, on a package that was genuinely importable at the time.

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

### When there is no manifest

This is the common case for something you just downloaded:

```
preflight check | random-repo\ | nothing was executed

  no manifest.json found

  This package makes no declarations preflight can check, so preflight
  can tell you nothing about it. That is not a verdict on the package;
  it is the absence of one.

  To adopt it anyway, write down what you will permit it to do:
      preflight init random-repo
```

`preflight init` writes a manifest skeleton so you can adopt an unmanaged package on your own terms. Be clear about what it does and does not do: it records **what you permit**, and it does not read the package's code to find out what the package wants. The generated `tools` list is empty, which means the package may expose none until you add them yourself.

```
preflight init ./weather
preflight check ./weather      # now there is something to check
```

It refuses to overwrite an existing manifest without `--force`, and it refuses outright when the folder name is not a valid Python identifier — `import weather-tool` is a syntax error, no manifest can fix that, and writing one anyway would produce a file that only looks like progress.

### `preflight demo`

Loads the four bundled example plugins and refuses three of them, so you can see the refusals rather than read about them:

```
preflight demo
```

---

## The manifest format

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
                                 // callable it is called; the result is the plugin.

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

**The registry gates on exactly three fields inside `plugin`:** `plugin_id`, `supported_platforms`, and `tools`. The rest — `permissions`, `data_classes`, `ui_contributions`, `migrations`, `health` — is metadata the *host* reads after a successful load. It is in the model so it is validated and type-checked rather than passed around as a loose dict, and it is documented here so nobody has to wonder why a load-gate carries a health field.

### Tool risk levels

`read` · `write` · `destructive` · `financial` · `credential` · `security` · `public_posting` · `sensitive_disclosure`

A risk level answers "what does the worst case look like if this tool gets called." It exists so a host can require confirmation, apply a policy, or refuse a whole tier of tool without having to guess from the tool's name.

**preflight does not act on it.** Nothing in the registry reads `risk`. It is a declaration you can build a policy on top of, not a policy.

### The plugin ABI

One member. That is the entire interface a plugin object must satisfy:

```python
@runtime_checkable
class Plugin(Protocol):
    @property
    def manifest(self) -> PluginManifest: ...
```

`runtime_checkable` makes `isinstance()` work here, but be precise about what that proves: it checks the attribute is *present*, not that it holds a `PluginManifest`. The real check is separate — the registry validates the reported manifest and requires it to equal the declared one.

### Release tiers (optional)

**Skip this if you ship one build.** Nothing above needs it, and the defaults handle the single-tier case.

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

## What it checks, in order — and the test for each

Every row names the test that proves it. If you doubt a row, run that test; if a row had no test, it would not be in this table.

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
| 14 | The confinement check is *what* stops the import — not something else that would have refused anyway | `test_the_confinement_check_is_what_stops_the_out_of_tree_import` |
| — | **Everything above this line happens with the plugin still inert on disk.** | |
| 15 | After importing, the module's real `__file__` is re-checked against `trusted_root` | `test_a_module_whose_file_changes_after_resolution_is_still_refused` |
| 16 | The loaded object actually satisfies the `Plugin` protocol | `test_an_entrypoint_returning_something_other_than_a_plugin_is_refused` |
| 17 | The manifest the object reports equals the manifest its file declared | `test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions` |
| 18 | On any refusal the registry is unmodified — no partial registration | asserted in every rejection test above (`registry.available() == ()`) |
| 19 | Everything handed back out is a deep copy; mutating it cannot reach the registry | `test_registry_loads_a_valid_plugin_and_rejects_manifest_or_tool_collisions` |
| 20 | `preflight check` reports on a package without importing it — including one that was importable at the time | `test_inspecting_a_package_never_imports_it`, `test_check_never_imports_the_package_it_is_pointed_at` |

Rows 1–14 are the point of the project. Rows 15–17 are what is left over — checks that *cannot* be made before the import, because they are about an object, and there is no object until something has been imported.

### About row 14

A security test that passes both with and without the fix proves nothing. `test_the_confinement_check_is_what_stops_the_out_of_tree_import` runs one scenario twice through the same harness and changes exactly one thing — which importer the registry is handed. The second importer is a copy of what this loader did *before* the confinement check existed, kept in the test file as a control condition.

The interesting result is not that the confined importer refuses the plugin. It is *when* the unconfined one does: it refuses it too, on a later and unrelated ground, having already run the plugin's top-level code. **Raising an exception is not the same as failing closed**, and that test is what tells the two apart.

---

## Worked examples

`examples/` contains four plugins. One of them deserves to load.

Every plugin package prints one line as the very first statement in its `__init__.py`. That turns the abstract claim into something you can *see*: the tripwires that appear in the output are exactly the plugins that got as far as being imported.

```
python examples/host.py        # or: preflight demo
```

```
  [greeter] top-level plugin code is executing
  [impostor] top-level plugin code is executing

preflight | plugins\ | 4 packages found

  LOADED   greeter     Greeter 1.0.0 - 1 tool
  REFUSED  trespasser  never imported
                       entrypoint module 'json' resolves to '<your-python>/Lib/json/__init__.py',
                       which is outside the trusted plugin root '.../examples/plugins'
  REFUSED  collider    never imported
                       tool name collision: 'greeter.hello' is already owned by 'greeter'
  REFUSED  impostor    imported, then rejected
                       runtime manifest for 'example.impostor' does not match its validated package manifest

  1 loaded, 3 refused -- 2 of the 3 stopped before any of their code ran

tool ownership is exclusive
  greeter.hello -> greeter
  impostor.read_profile -> None

calling the one plugin that loaded
  Hello, world.
```

The two tripwires print before the report because they fire during loading, while the report is assembled from what happened. Two plugins printed one; two never got the chance.

*(Only the absolute paths are shortened above — they are wherever you cloned this and whichever Python you ran it with. `tests/test_examples.py` runs this same script in a fresh interpreter and pins every outcome, because a quoted output is a claim.)*

**`greeter`** — valid. Loads, registers its tool, and answers when called.

**`trespasser`** — a directory containing a manifest and *no Python at all*. Its manifest sits inside the trusted root and passes every check that reads the file: canonical `package_id`, well-formed entrypoint, an acceptable visibility and ring. The only thing wrong with it is where its entrypoint points. Shape is not location: a manifest is allowed to *name* any module, and whether that module may be imported is decided separately, by resolving it to a file before the import happens.

**`collider`** — a perfectly good plugin that claims a tool name `greeter` already owns. Nothing is wrong with its code, which is the point: **`[collider]` never appears in the output.** It was refused from its manifest file alone, while still sitting inert on disk.

**`impostor`** — the honest one. Its manifest declares two read-only tools; the object it produces reports a third. Its manifest *file* is faultless, so it clears every pre-import check and gets imported — its tripwire fires. This is the one refusal that necessarily lands after the plugin's code has run, because the check compares the object's self-description to the file's, and there is no object to ask until the import has happened.

Be precise about what that last check is worth. preflight compares two *descriptions* of the plugin. It does not read the plugin's source, analyse its classes, or verify that a tool called `purge_all_records` does anything destructive — that name is a label chosen by whoever wrote the plugin. What the check buys you: a host builds its permission prompts, its tool list, and its UI from `registry.available()`, so without this a plugin could be approved on the strength of one manifest and then hand the host a different one. What it does not buy you: anything about behaviour. A plugin that describes itself accurately and then deletes your database registers without complaint.

---

## This is not a sandbox

Once a plugin is imported it is ordinary Python running in your process. It can read your files, open sockets, spawn processes, and monkey-patch you. There is no isolation here, no permission enforcement, and no way to take any of it back.

**preflight decides *whether* to import. It has no power after that.**

Everything in this README is about the decision at the door. If you need to constrain what a plugin does once it is inside, that is a different problem — a subprocess, a container, a WASM runtime, a separate machine — and preflight does not solve it and does not pretend to.

The two are complements, not alternatives. Isolation without a gate means running untrusted code and hoping the walls hold. A gate without isolation means the code you chose to run has the run of the place. Most projects have neither.

## Threat model

**Defends against**

- A plugin whose code contradicts its manifest — it is refused, and its tools are never registered, so the host never advertises capabilities the gate did not see.
- A plugin that claims a tool name another plugin already owns. Tool ownership is exclusive, so a plugin cannot shadow another plugin's tool and receive its calls.
- A plugin that leaks into a build tier it was never meant for — an experimental or internal plugin cannot register in a public build.
- A manifest inside the trusted root whose entrypoint names a module outside it. This includes dotted entrypoints, where resolving the child would otherwise import the parent as a side effect.
- A manifest carrying unknown fields, a manifest large enough to be an attack in itself, and a plugin whose id or tool names collide with something already loaded.

**Does not defend against**

- Anything a plugin does after it loads. See the section above; it is not a footnote.
- A compromised `trusted_root`. Write access to that directory is write access to your process. Everything here assumes you own it.
- A malicious or careless host. `load_manifest_file` accepts a custom `importer`, and a host that supplies its own has opted out of entrypoint confinement — deliberately, and it owns that decision.
- Supply-chain compromise of a plugin you allowlisted. preflight checks that a plugin is what it says it is; it has no opinion on whether you should have trusted it.
- Denial of service. A plugin that hangs at import time hangs your process.

**Assumes**

- You control `trusted_root` and its contents.
- You control the allowlist, and it is a decision rather than a formality.
- The Python interpreter and standard library are trustworthy.

## Why it exists

This was extracted from a personal AI assistant — a desktop application with several plugin packages and multiple build tiers, where a plugin in the wrong tier reaching a shipped build was a real failure mode rather than a hypothetical one. The loader had to answer "may this load here?" from the manifest alone, because by the time it could ask the plugin, the answer would not have mattered.

The extraction found a hole in the original, and the history keeps it: the first three commits land the loader with the bug, and the fourth closes it. Before the fix the manifest *file* was confined to the trusted root but the entrypoint *string* inside it was confined to nothing, so a manifest in the right place could name any importable module on `sys.path`. It is [`e0d2f8a`](../../commit/e0d2f8a), and `tests/test_negative_control.py` measures the difference rather than asserting it.

The reason this generalises beyond one desktop app is that dynamic plugin loading is currently exploding in agent tooling — MCP servers, agent skills, tool packs — and very little of it is gated. The manifest here already speaks that vocabulary (tools, risk levels, permissions) because that is what the original application needed it to describe. To be clear about the scope of that claim: this is a plugin trust boundary that happens to suit agent tooling, not an agent framework.

## FAQ

**Most things on GitHub have no manifest. What good is a loader that needs one?**
The question assumes preflight is something you point at other people's repositories. It is something you put inside your own program. If you are the host — the one deciding what may load — then you set the price of admission, and requiring a manifest is what every plugin system already does. The plugin author writes one because that is what loading in your application costs, the same way an extension author writes one because that is what loading in a browser costs. `check` and `init` cover the other case, a package that predates your decision to gate anything, and `init` is the adoption path rather than the product: you write down what you will permit, and then your loader holds that line whether or not the package agrees.

**Why not `importlib.metadata.entry_points()`?**
It is the standard answer and it is a good one when your plugins are packages you installed on purpose. But an entry point is a name resolved by importing it — reading the metadata tells you a module path, and finding out what is there means running it. The installation itself is the trust decision. preflight is for the case where the trust decision comes later than the installation: the files are already on disk, and something still has to decide whether today's build, on today's platform, is willing to run them.

**Why pydantic and not dataclasses or a JSON schema?**
Because the manifest is parsed from an untrusted file, and `extra="forbid"` is the behaviour that matters: an unknown field is rejected rather than silently dropped. An unknown field is either a typo or an attempt to smuggle something past the gate, and neither should load quietly. Pydantic gives that plus coercion and useful error messages in one dependency, and it is the only runtime dependency there is.

**Does this work with MCP servers?**
Not out of the box — MCP servers are usually separate processes speaking a protocol, and this is an in-process Python import gate. Where it does apply is one layer up: if you are the one deciding which servers or tool packs a build may launch, the manifest here already describes tools, risk levels, and permissions, and the gate already answers "is this package allowlisted, is it the right tier, does its tool name collide." Wiring that to a process launcher instead of an import is real work and this library does not do it.

**Why does my plugin directory need an `__init__.py`?**
Because a directory without one is a *namespace package*, and namespace packages have no single file on disk — `find_spec` reports `origin` as `None`. There is nothing to compare against `trusted_root`, so it fails closed and is refused. This is a real constraint on plugin layout and it is deliberate: the alternative is trusting a module whose location cannot be established.

**Why fail closed on built-in and frozen modules?**
Same reason. A built-in module reports `origin == "built-in"` and a frozen one reports `"frozen"`. Neither has a path that can be shown to be inside your trusted directory. A loader that trusts exactly one directory has no business making an exception for modules that are definitionally not in it.

**Can I supply my own importer?**
Yes — `load_manifest_file(..., importer=...)` is a documented seam, and it exists for hosts with their own import rules and for tests. Know what it costs: entrypoint confinement is a property of the *default* importer, so a host that replaces it owns that decision. Everything else in the pipeline still applies.

**`load_plugins` scans a directory. Isn't that the dangerous thing you warned about?**
An earlier version of this README argued against discovery outright, on the grounds that a `load_everything_in(directory)` helper would make the most dangerous configuration the most convenient one. That reasoning was aimed at the wrong half of the sentence. The danger was never *scanning* a folder — it was **loading whatever you found in it**. `load_plugins` scans, but `allow` is a required argument with no wildcard, so a package it discovers and a package it loads are different sets. Two tests pin that: `test_a_package_on_disk_but_not_in_allow_is_never_imported` and `test_an_empty_allowlist_loads_nothing_that_is_sitting_there`. What the scan removes is the hand-written `for` loop, not the decision.

**Can I use `preflight check` to tell whether something I downloaded is safe?**
No, and this is the most important limitation in this README. `check` reads a package's *declaration about itself* and reports whether that declaration is coherent — the manifest parses, the entrypoint points at a file inside the package, these are the tools it claims. It never reads the package's code. A package that describes itself accurately and then does something else passes every check in the command. It is a way to see what you are being asked to trust, not a verdict on whether to trust it.

**What if the thing I downloaded has no manifest?**
Then `check` will tell you it has nothing to check, which is the honest answer. `preflight init` writes a manifest skeleton so you can adopt the package on your own terms — but note whose judgement that is: the file records what *you* permit, and preflight did not read the code to fill it in.

**Do I have to understand editions, visibility, and release rings?**
No. They exist for applications that ship one plugin folder to several audiences, they are opt-in through `Policy(edition=...)`, and the defaults handle the single-tier case. Mark your plugins `public` / `stable` and the fields stop mattering.

**Why is there no config file?**
Because settings are host code, and host code is the one thing on this boundary a plugin cannot edit. A `preflight.toml` sitting next to your plugins would be a file that anyone who can write a plugin can also write, which puts your policy on the untrusted side of the line it is supposed to draw.

---

## Install

```
python -m pip install "preflight @ git+https://github.com/croresnos/preflight"
```

**Python 3.11+.** One runtime dependency: `pydantic>=2`. Installing puts a `preflight` command on your PATH; `python -m preflight` works too.

Run the tests from a clean clone with nothing installed but pytest:

```
git clone https://github.com/croresnos/preflight
cd preflight
python -m pip install pytest pydantic
python -m pytest -q
```

## A note on how this was built

Built with AI assistance. The threat model, the confinement design, and the decision to fail closed on any module that cannot be proven in-tree are mine — as is every line I would be asked to defend.

## License

MIT. See [LICENSE](LICENSE).
