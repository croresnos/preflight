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

rm -rf "$UAT"; mkdir -p "$UAT"; cd "$UAT"

# ---------------------------------------------------------------- install
section "1. Install from a clean tree"
mkdir -p tree && (cd "$SRC" && tar -cf - --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude=.omc .) | (cd tree && tar -xf -)
cd tree
"$PYEXE" -m venv .venv >/dev/null 2>&1
PY="$UAT/tree/.venv/Scripts/python.exe"
PF="$UAT/tree/.venv/Scripts/preflight.exe"
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
T=$("$PY" -m pytest -q 2>&1 | tail -2)
has "suite passes" "$T" "passed"
hasnt "no failures" "$T" "failed"
printf "        %s\n" "$(printf '%s' "$T" | tail -1)"

# ---------------------------------------------------------------- wheel
section "3. Wheel build -- demo must work from an installed wheel"
# This is where a real defect once hid: every test passed while `demo` was
# broken in every wheel, because the examples were not packaged.
cd "$UAT/tree"
"$PY" -m pip install -q build 2>&1 | grep -v notice
"$PY" -m build --wheel -o "$UAT/dist" >/dev/null 2>&1
WHL=$(ls "$UAT/dist"/*.whl 2>/dev/null | head -1)
check "wheel builds" "$([ -n "$WHL" ] && echo yes)" "yes"
mkdir -p "$UAT/wheeltest" && cd "$UAT/wheeltest"
"$PYEXE" -m venv .venv >/dev/null 2>&1
WPY="$UAT/wheeltest/.venv/Scripts/python.exe"
WPF="$UAT/wheeltest/.venv/Scripts/preflight.exe"
"$WPY" -m pip install -q "$WHL" 2>&1 | grep -v notice
D=$("$WPF" demo 2>&1)
has "demo runs from a wheel, outside any checkout" "$D" "5 packages found"
hasnt "demo does not ask you to clone the repo" "$D" "Clone the"
S=$("$WPF" settings 2>&1)
has "settings runs from a wheel" "$S" "preflight | settings"

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
touch pkgs/good/__init__.py; echo "raise SystemExit('PLUGIN CODE RAN')" > pkgs/good/plugin.py
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

printf "\n\033[1m===================== RESULT =====================\033[0m\n"
printf "  passed: %s\n  failed: %s\n" "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then printf "\n  failing checks:\n"; for n in "${FAILED_NAMES[@]}"; do printf "    - %s\n" "$n"; done; fi
[ "$FAIL" -eq 0 ] && printf "\n  \033[32mUAT PASSED\033[0m\n" || printf "\n  \033[31mUAT FAILED\033[0m\n"
exit "$FAIL"
