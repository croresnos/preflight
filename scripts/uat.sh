#!/usr/bin/env bash
# preflight UAT -- exercises the shipped artefact the way a stranger would.
# Nothing here imports preflight's internals; everything goes through the CLI
# or through a host script, because that is what a user actually touches.

# Usage:  bash scripts/uat.sh [python-executable]
#
# Builds a clean tree, a venv, and a wheel, then drives the shipped CLI the way
# a stranger would. It touches nothing in your checkout and writes only under
# its own scratch directory.
SRC="$(cd "$(dirname "$0")/.." && pwd)"
UAT="${PREFLIGHT_UAT_DIR:-${TMPDIR:-/tmp}/preflight-uat}"
PYEXE="${1:-$(command -v python3 || command -v python)}"
if [ -z "$PYEXE" ]; then echo "no python found; pass one as the first argument" >&2; exit 2; fi

PASS=0; FAIL=0; FAILED_NAMES=()

ok()   { PASS=$((PASS+1)); printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf "  \033[31mFAIL\033[0m  %s\n" "$1"; [ -n "$2" ] && printf "        %s\n" "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$3] got [$2]"; fi; }
has()  { if printf '%s' "$2" | grep -qF "$3"; then ok "$1"; else bad "$1" "missing: $3"; fi; }
hasnt(){ if printf '%s' "$2" | grep -qF "$3"; then bad "$1" "should not contain: $3"; else ok "$1"; fi; }
section(){ printf "\n\033[1m== %s\033[0m\n" "$1"; }
venv_python(){
  if [ -x "$1/Scripts/python.exe" ]; then printf '%s\n' "$1/Scripts/python.exe"
  else printf '%s\n' "$1/bin/python"; fi
}
venv_preflight(){
  if [ -x "$1/Scripts/preflight.exe" ]; then printf '%s\n' "$1/Scripts/preflight.exe"
  else printf '%s\n' "$1/bin/preflight"; fi
}

rm -rf "$UAT"; mkdir -p "$UAT"; cd "$UAT"

# ---------------------------------------------------------------- install
section "1. Install from a clean tree"
mkdir -p tree && (cd "$SRC" && tar -cf - --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=.omc .) | (cd tree && tar -xf -)
cd tree
"$PYEXE" -m venv .venv >/dev/null 2>&1
PY=$(venv_python "$UAT/tree/.venv")
PF=$(venv_preflight "$UAT/tree/.venv")
"$PY" -m pip install -q -e . 2>&1 | grep -v notice
"$PY" -m pip install -q pytest 2>&1 | grep -v notice
check "editable install exposes the console script" "$([ -f "$PF" ] && echo yes)" "yes"
# Read the expected version rather than hardcoding it: this line was still
# asserting 0.5.0 after the release that made it 0.6.0, which is the sort of
# thing a UAT is supposed to catch rather than commit.
VERSION=$(grep -m1 '^__version__' "$SRC/src/preflight/__init__.py" | cut -d'"' -f2)
V=$("$PF" --version 2>&1)
check "--version reports $VERSION" "$V" "preflight $VERSION"
# The distribution is preflight-gate; the import and the command are preflight.
DEPS=$("$PY" -m pip show preflight-gate 2>/dev/null | grep -i '^Requires:' | sed 's/Requires: //')
check "exactly one runtime dependency" "$DEPS" "pydantic"

section "2. Test suite in the fresh venv"
T_FILE="$UAT/pytest.txt"
"$PY" -m pytest -q >"$T_FILE" 2>&1
T_RC=$?
T=$(tail -2 "$T_FILE")
check "suite exits successfully" "$T_RC" "0"
has "suite passes" "$T" "passed"
hasnt "no failures" "$T" "failed"
printf "        %s\n" "$(printf '%s' "$T" | tail -1)"

# ---------------------------------------------------------------- wheel
section "3. Wheel build -- demo must work from an installed wheel"
# This is where a real defect once hid: every test passed while `demo` was
# broken in every wheel, because the examples were not packaged.
cd "$UAT/tree"
"$PY" -m pip install -q build 2>&1 | grep -v notice
"$PY" -m build -o "$UAT/dist" >/dev/null 2>&1
WHL=$(ls "$UAT/dist"/*.whl 2>/dev/null | head -1)
SDIST=$(ls "$UAT/dist"/*.tar.gz 2>/dev/null | head -1)
check "wheel builds" "$([ -n "$WHL" ] && echo yes)" "yes"
check "sdist builds" "$([ -n "$SDIST" ] && echo yes)" "yes"
if tar -tf "$SDIST" | grep -Eq '(^|/)(\.omc|\.git|\.coverage|\.pytest_cache)(/|$)'; then
  bad "sdist excludes local and secret-bearing state" "forbidden path found"
else
  ok "sdist excludes local and secret-bearing state"
fi
mkdir -p "$UAT/wheeltest" && cd "$UAT/wheeltest"
"$PYEXE" -m venv .venv >/dev/null 2>&1
WPY=$(venv_python "$UAT/wheeltest/.venv")
WPF=$(venv_preflight "$UAT/wheeltest/.venv")
"$WPY" -m pip install -q "$WHL" 2>&1 | grep -v notice
D=$("$WPF" demo 2>&1)
has "demo runs from a wheel, outside any checkout" "$D" "5 packages found"
hasnt "demo does not ask you to clone the repo" "$D" "Clone the"
S=$("$WPF" settings 2>&1)
has "settings runs from a wheel" "$S" "preflight | settings"

mkdir -p "$UAT/sdisttest" && cd "$UAT/sdisttest"
"$PYEXE" -m venv .venv >/dev/null 2>&1
SPY=$(venv_python "$UAT/sdisttest/.venv")
SPF=$(venv_preflight "$UAT/sdisttest/.venv")
"$SPY" -m pip install -q "$SDIST" 2>&1 | grep -v notice
SV=$("$SPF" --version 2>&1)
check "sdist installs outside the checkout" "$SV" "preflight $VERSION"

# ---------------------------------------------------------------- demo
section "4. demo -- the refusals that are the product"
D=$("$PF" demo 2>&1)
has "five packages found" "$D" "5 packages found"
has "2 loaded, 3 refused" "$D" "2 loaded, 3 refused"
has "the inert/ran distinction is reported" "$D" "stopped before any of their code ran"
has "trespasser never imported" "$D" "REFUSED  trespasser  never imported"
has "impostor imported then rejected" "$D" "REFUSED  impostor    imported, then rejected"
DR=$("$PF" demo --refuse destructive 2>&1)
has "--refuse destructive refuses a fourth" "$DR" "1 loaded, 4 refused"
has "janitor stopped while inert" "$DR" "REFUSED  janitor     never imported"
has "the declared-vs-concealed lesson is printed" "$DR" "does not detect concealment"

# ---------------------------------------------------------------- try
section "5. try -- the sandbox, and its three documented breaks"
cd "$UAT"
TOUT=$("$PF" try box 2>&1)
has "try writes a host" "$TOUT" "host.py"
has "try names the three breaks" "$TOUT" "misspell the entrypoint"
cd "$UAT/box"
R=$("$PY" host.py 2>&1)
has "the sandbox loads as written" "$R" "1 loaded, 0 refused"
has "and the plugin answers" "$R" "18C and raining"

rm -f plugins/weather/__init__.py
R=$("$PY" host.py 2>&1)
has "break 1 refused" "$R" "0 loaded, 1 refused"
has "break 1 refused while inert" "$R" "never imported"
touch plugins/weather/__init__.py     # the documented undo
R=$("$PY" host.py 2>&1)
has "break 1 undo restores it" "$R" "1 loaded, 0 refused"

sed -i 's/weather\.plugin/wether.plugin/' plugins/weather/manifest.json
R=$("$PY" host.py 2>&1)
has "break 2 refused while inert" "$R" "never imported"
sed -i 's/wether\.plugin/weather.plugin/' plugins/weather/manifest.json
R=$("$PY" host.py 2>&1)
has "break 2 undo restores it" "$R" "1 loaded, 0 refused"

sed -i 's/"1\.0\.0"/"2.0.0"/' plugins/weather/plugin.py
R=$("$PY" host.py 2>&1)
has "break 3 refused" "$R" "0 loaded, 1 refused"
has "break 3 caught only after import" "$R" "imported, then rejected"
sed -i 's/"2\.0\.0"/"1.0.0"/' plugins/weather/plugin.py
R=$("$PY" host.py 2>&1)
has "break 3 undo restores it (the stale-pyc bug)" "$R" "1 loaded, 0 refused"

# ---------------------------------------------------------------- check
section "6. check -- exit codes and safety"
cd "$UAT"; mkdir -p work && cd work && git init -q .
export APPDATA="$UAT/work/_cfg"
mkdir -p pkgs/good
cat > pkgs/good/manifest.json <<'EOF'
{"schema_version":"1.0","package_id":"local.good","core_api_version":"1.0","visibility":"public","release_ring":"stable","entrypoint":"good.plugin:create_plugin","plugin":{"schema_version":"1.0","plugin_id":"good","name":"Good","module_version":"1.0.0","tools":[{"name":"good.pay","risk":"financial"}]}}
EOF
touch pkgs/good/__init__.py
# The entrypoint has to be genuinely there -- `check` now verifies the attribute
# half as well as the module half, and a fixture missing it would be testing that
# instead of what this section is about. The raise stays underneath it: it is the
# tripwire, and it fires on import whatever is defined above it.
cat > pkgs/good/plugin.py <<'EOF'
def create_plugin():
    return None


raise SystemExit('PLUGIN CODE RAN')
EOF
"$PF" check pkgs/good >/dev/null 2>&1; check "check exits 0 on coherent paperwork" "$?" "0"
O=$("$PF" check pkgs/good 2>&1)
hasnt "check did NOT execute the package" "$O" "PLUGIN CODE RAN"
has "check says nothing was executed" "$O" "nothing was executed"
"$PF" check pkgs/good --refuse financial >/dev/null 2>&1; check "check exits 1 on a refused risk" "$?" "1"
"$PF" check ./nope >/dev/null 2>&1; check "check exits 2 on a missing path" "$?" "2"
echo x > afile; "$PF" check afile >/dev/null 2>&1; check "check exits 2 on a file" "$?" "2"
O=$("$PF" check ./nope 2>&1); has "missing path is told apart from a file" "$O" "does not exist"
"$PF" check pkgs/good --refuse nonsense >/dev/null 2>&1; check "unknown risk name exits 2" "$?" "2"

# ---------------------------------------------------------------- settings
section "7. settings -- the new surface"
O=$("$PF" settings 2>&1)
has "defaults shown with origins" "$O" "default"
has "scope note on the show screen" "$O" "It does not apply to a"
O=$("$PF" settings --where 2>&1)
has "--where names both files" "$O" "not created yet"
"$PF" settings refuse financial,write >/dev/null 2>&1; check "saving a rule exits 0" "$?" "0"
O=$("$PF" settings 2>&1)
has "saved rule is reported" "$O" "financial, write"
has "and its origin is the project file" "$O" "project"
"$PF" check pkgs/good >/dev/null 2>&1; check "saved rule applies to check with no flag" "$?" "1"
"$PF" check pkgs/good --refuse destructive >/dev/null 2>&1; check "a flag REPLACES the saved rule" "$?" "0"
"$PF" settings --profile prod refuse financial,destructive >/dev/null 2>&1
"$PF" check pkgs/good --profile prod >/dev/null 2>&1; check "a profile applies" "$?" "1"
N=$(ls *.json 2>/dev/null | wc -l); check "profiles live in the one file" "$N" "1"
"$PF" settings --profile nope >/dev/null 2>&1; check "an unknown profile exits 2" "$?" "2"
"$PF" settings refuse --clear >/dev/null 2>&1
"$PF" check pkgs/good >/dev/null 2>&1; check "--clear falls back" "$?" "0"
echo '{not json' > preflight.settings.json
"$PF" settings >/dev/null 2>&1; check "malformed JSON exits 2, not 1" "$?" "2"
O=$("$PF" settings 2>&1); hasnt "malformed JSON gives no traceback" "$O" "Traceback"
echo '{"version":1,"allow":["x.y"]}' > preflight.settings.json
O=$("$PF" settings 2>&1); has "an allow key is refused with a reason" "$O" "may not"
rm -f preflight.settings.json
"$PF" settings refuse financial,write >/dev/null 2>&1

# ---------------------------------------------------------------- bridge
section "8. --as-python -- the bridge, executed not matched"
"$PF" settings --as-python > pasted.py 2>&1
has "prints a Policy line" "$(cat pasted.py)" "refuse_tool_risks={ToolRisk.FINANCIAL, ToolRisk.WRITE}"
mkdir -p bridge/plugins/weather && cd bridge
cp -r "$UAT/box/plugins/weather" plugins/ 2>/dev/null
"$PY" - <<'PY'
import json,pathlib
m=pathlib.Path("plugins/weather/manifest.json"); d=json.loads(m.read_text())
d["plugin"]["tools"]=[{"name":"weather.buy","risk":"financial"}]
m.write_text(json.dumps(d,indent=2))
p=pathlib.Path("plugins/weather/plugin.py")
p.write_text(p.read_text().replace('{"name": "weather.today", "risk": "read"}','{"name": "weather.buy", "risk": "financial"}'))
s=pathlib.Path("../pasted.py").read_text()
s=s.replace('"plugins",','PLUGINS,').replace('allow=["acme.weather"],       # required, and there is no wildcard','allow=["local.weather"],')
s=("import sys\nfrom pathlib import Path\nPLUGINS=Path(__file__).resolve().parent/'plugins'\nsys.path.insert(0,str(PLUGINS))\n")+s+"\nprint(result)\n"
pathlib.Path("host.py").write_text(s)
PY
R=$("$PY" host.py 2>&1)
has "the pasted host refuses the same package" "$R" "0 loaded, 1 refused"
has "and refuses it before any code ran" "$R" "1 of the 1 stopped before any of their code ran"
cd "$UAT/work"

# ---------------------------------------------------------------- security
section "9. Security -- a settings file must not configure the gate"
mkdir -p dl/evil
cat > dl/evil/manifest.json <<'EOF'
{"schema_version":"1.0","package_id":"local.evil","core_api_version":"1.0","visibility":"public","release_ring":"stable","entrypoint":"evil.plugin:create_plugin","plugin":{"schema_version":"1.0","plugin_id":"evil","name":"Evil","module_version":"1.0.0","tools":[{"name":"evil.pay","risk":"financial"}]}}
EOF
touch dl/evil/__init__.py; echo "def create_plugin(): pass" > dl/evil/plugin.py
POISON='{"version":1,"refuse":[]}'
echo "$POISON" > dl/evil/preflight.settings.json
echo "$POISON" > dl/preflight.settings.json
for d in "$UAT/work" "$UAT/work/dl" "$UAT/work/dl/evil"; do
  cd "$d"; "$PF" check "$UAT/work/dl/evil" >/dev/null 2>&1
  check "planted file fails from cwd=${d##*/}" "$?" "1"
done
cd "$UAT/work/dl"
O=$("$PF" check "$UAT/work/dl/evil" 2>&1 >/dev/null)
has "and preflight says why it ignored the file" "$O" "ignoring"
cd "$UAT/work"

# load_plugins must be untouched by any of it
mkdir -p iso/plugins/weather && cd iso
cp -r "$UAT/box/plugins/weather" plugins/ 2>/dev/null
echo '{"version":1,"refuse":["read"]}' > preflight.settings.json
cat > host.py <<'EOF'
import sys
from pathlib import Path
from preflight import load_plugins
P = Path(__file__).resolve().parent / "plugins"
sys.path.insert(0, str(P))
print(load_plugins(P, allow=["local.weather"]))
EOF
R=$("$PY" host.py 2>&1)
has "load_plugins ignores a settings file that refuses its risk" "$R" "1 loaded, 0 refused"
cd "$UAT/work"

# ---------------------------------------------------------------- create
section "10. create -- writing paperwork for a package that has none"
mkdir -p adopt/thing && cd adopt
"$PF" create thing >/dev/null 2>&1; check "create writes a manifest" "$?" "0"
check "manifest exists" "$([ -f thing/manifest.json ] && echo yes)" "yes"
"$PF" create thing >/dev/null 2>&1; check "create refuses to overwrite" "$?" "2"
"$PF" create thing --force >/dev/null 2>&1; check "--force overwrites" "$?" "0"
mkdir -p "bad-name"
O=$("$PF" create bad-name 2>&1); "$PF" create bad-name >/dev/null 2>&1
check "a folder that cannot be a module exits 2" "$?" "2"
has "and says to rename it" "$O" "Rename the folder first"
"$PF" create missing-entirely >/dev/null 2>&1; check "create on a missing folder exits 2" "$?" "2"
cd "$UAT/work"

# ---------------------------------------------------------------- docs
section "11. Docs -- every command quoted in the manual actually runs"
MAN="$SRC/docs/MANUAL.md"
check "manual has section 12" "$(grep -c '^## 12\. Saving your settings' "$MAN")" "1"
check "manual has section 13" "$(grep -c '^## 13\. preflight inside an agent' "$MAN")" "1"
check "TOC lists 13" "$(grep -c '13. \[preflight inside an agent\]' "$MAN")" "1"
check "README no longer claims there is no config file" "$(grep -c 'There is no configuration file' "$SRC/README.md")" "0"
check "Policy docstring no longer claims it either" "$(grep -c 'There is no configuration file' "$SRC/src/preflight/load.py")" "0"
check "manual documents the forgeable-marker limit" "$(grep -c 'it is a filter, not a' "$MAN")" "1"
check "manual names the unforgeable anchor" "$(grep -c 'cannot be forged is your' "$MAN")" "1"
check "manual has the check table" "$(grep -c '^## 14\. What it checks' "$MAN")" "1"
check "manual has why-it-exists" "$(grep -c '^## 15\. Why it exists' "$MAN")" "1"
# The install line is the one instruction nobody can verify before following it,
# and `pip install preflight` fetches an unrelated 2015 Django package.
check "no doc says to install the wrong package" \
  "$(grep -h 'pip install preflight$' "$SRC/README.md" "$MAN" | wc -l | tr -d ' ')" "0"
check "README names the real distribution" \
  "$([ "$(grep -c 'pip install preflight-gate' "$SRC/README.md")" -ge 1 ] && echo yes)" "yes"
check "manual names it too" \
  "$([ "$(grep -c 'pip install preflight-gate' "$MAN")" -ge 1 ] && echo yes)" "yes"
check "README leads with who it is for" "$(grep -c 'Is this for you' "$SRC/README.md")" "1"

section "12. check agrees with the gate"
mkdir -p "$UAT/work/tiers/exp" && cd "$UAT/work/tiers/exp"
: > __init__.py
printf 'def create_plugin():\n    return None\n' > plugin.py
printf '{"package_id":"probe.exp","core_api_version":"1.0","visibility":"public",' > manifest.json
printf '"release_ring":"experimental","entrypoint":"exp.plugin:create_plugin",' >> manifest.json
printf '"plugin":{"plugin_id":"exp","name":"E","module_version":"1.0.0"}}' >> manifest.json
cd "$UAT/work/tiers"
O=$("$PF" check exp 2>&1); RC=$?
check "check exits 1 on a ring this build refuses" "$RC" "1"
has "and quotes the gate's own sentence" "$O" "from the 'experimental' release ring"
cd "$UAT/work"

# A folder named after a module the interpreter already owns. The paperwork is
# perfect and the file is right there, so `check` used to resolve it by path
# arithmetic and exit 0 -- on a package no host can reach by that name. Two
# regimes, because the gate reaches them by different routes: `time` is compiled
# in and reports no file at all, `json` is on disk and resolves to the standard
# library's copy.
for NAME in time json; do
  mkdir -p "$UAT/work/shadow/$NAME" && cd "$UAT/work/shadow/$NAME"
  : > __init__.py
  printf 'def create_plugin():\n    return None\n' > plugin.py
  printf '{"package_id":"probe.%s","core_api_version":"1.0","visibility":"public",' "$NAME" > manifest.json
  printf '"release_ring":"stable","entrypoint":"%s.plugin:create_plugin",' "$NAME" >> manifest.json
  printf '"plugin":{"plugin_id":"%s","name":"S","module_version":"1.0.0"}}' "$NAME" >> manifest.json
  cd "$UAT/work/shadow"
  O=$("$PF" check "$NAME" 2>&1); RC=$?
  check "check exits 1 on a folder named '$NAME'" "$RC" "1"
  has "and says to rename it ($NAME)" "$O" "Rename the plugin folder"
done
# The negative half: a name that merely starts with a stdlib word still loads.
mkdir -p "$UAT/work/shadow/jsonish" && cd "$UAT/work/shadow/jsonish"
: > __init__.py
printf 'def create_plugin():\n    return None\n' > plugin.py
printf '{"package_id":"probe.jsonish","core_api_version":"1.0","visibility":"public",' > manifest.json
printf '"release_ring":"stable","entrypoint":"jsonish.plugin:create_plugin",' >> manifest.json
printf '"plugin":{"plugin_id":"jsonish","name":"S","module_version":"1.0.0"}}' >> manifest.json
cd "$UAT/work/shadow"
"$PF" check jsonish > /dev/null 2>&1
check "a name that only looks like stdlib still passes" "$?" "0"
cd "$UAT/work"

section "13. the entrypoint's two shapes"
# A package that has never heard of preflight: no create_plugin anywhere. The
# colon form names an attribute nothing defines, so a host imports it and only
# then refuses it -- the exact case `check` used to pass with exit 0.
mkdir -p "$UAT/work/adopt/notepad" && cd "$UAT/work/adopt/notepad"
cat > __init__.py <<'PYFILE'
def jot(text):
    return "noted: " + text
PYFILE
cd "$UAT/work/adopt"
O=$("$PF" create notepad 2>&1)
has "create says the package does not report its own manifest" "$O" "does not report its own manifest"
check "and the entrypoint it wrote has no colon" "$(grep -c '"entrypoint": "notepad"' notepad/manifest.json)" "1"
O=$("$PF" check notepad 2>&1); RC=$?
check "check exits 0 on the adapted form" "$RC" "0"
has "and says the waiver out loud" "$O" "adapted by preflight"

# Now point the entrypoint at an attribute that is not there.
"$PY" - <<'PYFILE'
import json, pathlib
p = pathlib.Path("notepad/manifest.json")
m = json.loads(p.read_text())
m["entrypoint"] = "notepad:create_plugin"
p.write_text(json.dumps(m, indent=2))
PYFILE
O=$("$PF" check notepad 2>&1); RC=$?
check "check exits 1 when the named attribute is missing" "$RC" "1"
has "and files it as a refusal that costs the import" "$O" "AFTER importing it"

# --adapter buys check 17 back, and must not overwrite anybody's Python.
mkdir -p "$UAT/work/adopt/owned" && cd "$UAT/work/adopt/owned"
: > __init__.py
cd "$UAT/work/adopt"
"$PF" create owned --adapter > /dev/null 2>&1
check "--adapter writes a plugin.py" "$([ -f owned/plugin.py ] && echo yes || echo no)" "yes"
"$PF" check owned > /dev/null 2>&1
check "and the pair it wrote passes check" "$?" "0"
echo mine > owned/plugin.py
"$PF" create owned --adapter --force > /dev/null 2>&1
check "--adapter refuses to overwrite a plugin.py" "$?" "2"
check "and leaves it alone" "$(cat owned/plugin.py)" "mine"
cd "$UAT/work"

section "14. try will not take a folder over"
mkdir -p "$UAT/work/mywork" && cd "$UAT/work"
echo "my own work" > mywork/host.py
"$PF" try mywork > /dev/null 2>&1
check "try refuses a folder it did not write" "$?" "2"
"$PF" try mywork --force > /dev/null 2>&1
check "and --force does not override that" "$?" "2"
check "the hand-written host.py survives" "$(cat mywork/host.py)" "my own work"
"$PF" try uatbox > /dev/null 2>&1
check "try writes a fresh sandbox" "$?" "0"
check "including break.py" "$([ -f uatbox/break.py ] && echo yes || echo no)" "yes"
"$PF" try uatbox --force > /dev/null 2>&1
check "and --force still resets its own sandbox" "$?" "0"
cd "$UAT/work/uatbox"
"$PY" host.py > /dev/null 2>&1
check "the sandbox host exits 0 while it loads" "$?" "0"
"$PY" break.py 2 > /dev/null 2>&1
"$PY" host.py > /dev/null 2>&1
check "and non-zero once broken" "$?" "1"
"$PY" break.py 2 --undo > /dev/null 2>&1
"$PY" host.py > /dev/null 2>&1
check "and 0 again after the undo" "$?" "0"
cd "$UAT/work"


printf "\n\033[1m===================== RESULT =====================\033[0m\n"
printf "  passed: %s\n  failed: %s\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then printf "\n  failing checks:\n"; for n in "${FAILED_NAMES[@]}"; do printf "    - %s\n" "$n"; done; fi
[ "$FAIL" -eq 0 ] && printf "\n  \033[32mUAT PASSED\033[0m\n" || printf "\n  \033[31mUAT FAILED\033[0m\n"
exit "$FAIL"
