# preflight

**Decide whether a plugin is allowed to load by reading its manifest file — before a single line of the plugin's code runs.**

### Is this for you?

**Does your Python program load plugins from a folder?** If not, preflight has no
job in it, and the rest of this page will not change that.

preflight is a library. There is no app, no daemon, and no config file. You add one
function call to your program's startup, and from then on it decides which plugins
may be imported. That is the whole product.

It needs exactly three things:

1. Your program has a `plugins/` folder.
2. Each plugin subfolder has a `manifest.json` — written by its author, because your
   application requires one, or by you with `preflight create`.
3. Your startup code calls `load_plugins`.

**What it is not:** it does not gate pip packages, npm packages, MCP servers, or an
agent's built-in tools. It does not read plugin code, so it cannot detect malware.
It is a permission system for a plugin folder you own — the same shape as a browser
extension manifest.

---

## Why the manifest has to be a file

Importing a Python module runs it. So a loader that imports a plugin in order to
find out what it is has already let it do whatever it was going to do:

```python
module = importlib.import_module(plugin_name)   # <-- the plugin's code has now run
if module.MANIFEST["version"] not in SUPPORTED: # <-- too late
    raise RuntimeError("unsupported plugin")
```

There is no "import but don't execute" in Python. If the only description of a
plugin lives *inside* the plugin, you have to run the plugin to read it. So
preflight requires the description to live outside it, in inert JSON, and makes
every decision from that file before anything is imported.

## Watch it refuse things

```
pip install preflight-gate
preflight demo
```

```
  [greeter] top-level plugin code is executing
  [impostor] top-level plugin code is executing
  [janitor] top-level plugin code is executing

preflight | plugins\ | 5 packages found

  LOADED   greeter     Greeter 1.0.0 - 1 tool
  REFUSED  trespasser  never imported
                       entrypoint module 'json' resolves to '<python>\Lib\json\__init__.py',
                       which is outside the trusted plugin root '<root>'
  REFUSED  collider    never imported
                       tool name collision: 'greeter.hello' is already owned by 'greeter'
  REFUSED  impostor    imported, then rejected
                       runtime manifest for 'example.impostor' does not match its
                       validated package manifest
  LOADED   janitor     Janitor 1.0.0 - 1 tool

  2 loaded, 3 refused -- 2 of the 3 stopped before any of their code ran
```

Each example plugin prints a tripwire as the first statement of its `__init__.py`.
Three tripwires fired; five plugins were considered. **The two refusals with no
tripwire are the point of the project** — those plugins were turned away while
still inert text on disk.

`never imported` and `imported, then rejected` are both normal output, because the
difference between them is the honest measure of what preflight did for you.
`Outcome.code_ran` records it from the run itself rather than guessing from which
error came back.

## The gate

```
myapp/
├── host.py
└── plugins/                 <- the trusted root
    └── greeter/
        ├── __init__.py      <- required; a namespace package has no file to check
        ├── plugin.py
        └── manifest.json
```

`plugins/greeter/manifest.json`:

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

print(result)
print(result.plugins["greeter"].hello("world"))  # Hello, world.
```

Three things that are load-bearing and easy to miss:

- **`allow` is required and has no wildcard.** A package sitting in the folder but
  absent from `allow` is discovered, reported, and never imported. Discovery saves
  you the `for` loop; it is the allowlist, not the absence of a scan, that keeps an
  unexpected folder from loading.
- **The order of `allow` is the order things load,** and the first plugin to claim a
  tool name keeps it. Precedence is something you wrote down rather than something
  the filesystem decided alphabetically.
- **The directory you pass is the security boundary.** Every manifest must be inside
  it and every entrypoint must resolve to a file inside it. If you point it at a
  directory anyone can write to, none of the rest of this matters.

[**The manual**](docs/MANUAL.md) builds this from an empty directory and has an
entry for [every message preflight can print](docs/MANUAL.md#7-every-message-and-what-to-do-about-it).

### Policy

Every default is the strictest value available, so a call passing no `Policy` is the
safest call you can make.

```python
from preflight import Policy, ToolRisk, load_plugins

result = load_plugins(
    "plugins",
    allow=["example.greeter"],
    policy=Policy(refuse_tool_risks={ToolRisk.DESTRUCTIVE, ToolRisk.FINANCIAL}),
)
```

**`Policy` is never loaded from disk, and that is deliberate:** a settings file
living next to your plugins would be a file a plugin could write, which would put
your policy on the untrusted side of the boundary it is meant to draw. A host states
its policy in its own source, where it is reviewable and diffable. To vary it per
deployment, read *your own* configuration and build a `Policy` from it —
[preflight inside an agent](docs/MANUAL.md#13-preflight-inside-an-agent).

## The two moments

Confusing these is the single easiest way to misread this project:

| When | What | Who runs it |
|---|---|---|
| **Once**, when you adopt a plugin | `preflight check`, `preflight create`, `preflight try` | you, at a terminal |
| **Every launch, for the life of the program** | `load_plugins(...)` | your code, automatically |

The second row is preflight. The first row is the on-ramp — a way to read what you
are being asked to trust, and to write down what you will permit, before the gate in
the second row ever sees it. **None of the terminal commands protect a running
application, because none of them are running when it is.**

```
preflight check ./thing     # read its manifest and every tool it claims
preflight create ./thing    # write a manifest, when it has none
preflight try ./sandbox     # a working host and plugin, and three ways to break them
preflight demo              # five example plugins, three of them refused
preflight settings          # save the rules, per project and per agent
```

`check` **imports nothing** — not the plugin, not `importlib`, not even `find_spec`.
The entrypoint is resolved by path arithmetic against the folder on disk, so no code
path through the command can cause the inspected package to execute;
`tests/test_inspect.py` proves it with a tripwire on a package that was genuinely
importable at the time. It exits `0` when a package would load, `1` when it would be
refused, and `2` on a bad path — so it drops into CI without anyone reading the
output. Full reference: [Command line](docs/MANUAL.md#9-command-line-reference).

## Building an agent?

The manifest here already speaks that vocabulary — tools, risk levels, permissions —
because the application this was extracted from needed it to. If you are gating a
folder of tool packs or skills that your agent imports at startup, that is the same
problem, and [MANUAL §13](docs/MANUAL.md#13-preflight-inside-an-agent) is the recipe.

Two caveats. **MCP servers are usually separate processes speaking a protocol**, and
this is an in-process Python import gate — wiring it to a process launcher is real
work this library does not do. And this is a plugin trust boundary that happens to
suit agent tooling, not an agent framework.

## What it checks

Every decision above the line is made from files on disk, and no file executes
before it has cleared the boundary.

| | Check |
|---|---|
| 1–4 | The manifest is inside the trusted root, under 256 KiB, valid JSON, and validates against a **closed** schema — an unknown field is a refusal, not a shrug |
| 5 | `package_id` is on the build's explicit allowlist, and load order follows it |
| 6–8 | The platform, `visibility` and `release_ring` are ones this build accepts, and a declared tool risk the host refuses stops the package here |
| 9–11 | No `plugin_id` or tool name collides with something already registered |
| 12–14 | The entrypoint module — **and every parent package on the way to it** — resolves to a file inside the trusted root, located without being executed |
| — | ─────── *only now is anything imported* ─────── |
| 15–17 | The module's real `__file__` is re-checked, the object satisfies the `Plugin` protocol, and the manifest it reports equals the one its file declared |
| 18–19 | On any refusal the registry is unmodified, and everything handed back is a deep copy |

Rows 15–17 are what is left over — checks that *cannot* be made before the import,
because they are about an object, and there is no object until something has been
imported.

**[The full table names the test that proves each row.](docs/MANUAL.md#14-what-it-checks-in-order--and-the-test-for-each)**
If you doubt a row, run that test; if a row had no test, it would not be in the table.

## This is not a sandbox

Once a plugin is imported it is ordinary Python running in your process. It can read
your files, open sockets, spawn processes, and monkey-patch you. There is no
isolation here, no permission enforcement, and no way to take any of it back.

**preflight decides *whether* to import. It has no power after that.**

The two are complements, not alternatives. Isolation without a gate means running
untrusted code and hoping the walls hold. A gate without isolation means the code you
chose to run has the run of the place. Most projects have neither.

## Threat model

**Defends against**

- A plugin whose code contradicts its manifest — it is refused, and its tools are never registered, so the host never advertises capabilities the gate did not see.
- A plugin that claims a tool name another plugin already owns. Tool ownership is exclusive, so a plugin cannot shadow another plugin's tool and receive its calls.
- A plugin that leaks into a build tier it was never meant for — an experimental or internal plugin cannot register in a public build.
- A manifest inside the trusted root whose entrypoint names a module outside it. This includes dotted entrypoints, where resolving the child would otherwise import the parent as a side effect.
- A manifest carrying unknown fields, a manifest large enough to be an attack in itself, and a plugin whose id or tool names collide with something already loaded.

**Does not defend against**

- Anything a plugin does after it loads. See the section above; it is not a footnote.
- A compromised trusted root. Write access to that directory is write access to your process. Everything here assumes you own it.
- A malicious or careless host. `load_manifest_file` accepts a custom `importer`, and a host that supplies its own has opted out of entrypoint confinement — deliberately, and it owns that decision.
- Supply-chain compromise of a plugin you allowlisted. preflight checks that a plugin is what it says it is; it has no opinion on whether you should have trusted it.
- Denial of service. A plugin that hangs at import time hangs your process.

**Assumes** you control the trusted root and its contents; that the allowlist is a
decision rather than a formality; and that the interpreter and standard library are
trustworthy.

## Install

```
pip install preflight-gate
```

**Python 3.11+.** One runtime dependency: `pydantic>=2`.

The distribution is `preflight-gate`; the import, the command, and the manifest
schema are all `preflight`. PyPI's `preflight` is an unrelated Django project last
released in 2015, so that name was never available. You type the long one once.

The examples ship inside the distribution, so `preflight demo` runs from an installed
copy with no clone. `python -m preflight` works if you would rather not depend on the
console script. Installing with [pipx](https://pipx.pypa.io) puts the command on your
PATH regardless of which virtualenv is active.

Run the tests from a clean clone:

```
git clone https://github.com/croresnos/preflight
cd preflight
python -m pip install pytest pydantic
python -m pytest -q
```

## More

- [**The manual**](docs/MANUAL.md) — install, first host, first refusal, and an entry for every message
- [Every message and what to do about it](docs/MANUAL.md#7-every-message-and-what-to-do-about-it)
- [The manifest format](docs/MANUAL.md#10-the-manifest-format), field by field
- [Questions that come up in practice](docs/MANUAL.md#8-questions-that-come-up-in-practice) — why pydantic, why `__init__.py` is required, why there is no config file, whether `check` can tell you something is safe (it cannot)
- [Why this exists, and the bug the history keeps](docs/MANUAL.md#15-why-it-exists)

## A note on how this was built

Built with AI assistance. The threat model, the confinement design, and the decision
to fail closed on any module that cannot be proven in-tree are mine — as is every
line I would be asked to defend.

## License

MIT. See [LICENSE](LICENSE).
