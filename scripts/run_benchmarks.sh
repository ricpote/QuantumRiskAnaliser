#!/usr/bin/env bash
# Rebuild and run every external benchmark, one at a time (light on memory), and print each score.
#   scripts/run_benchmarks.sh [workdir]        (default: ~/.cache/quantumtrace-bench; clones are reused)
# Needs git and Java (Apache benchmark: the jars are decompiled with CFR). Bandit is installed in a venv under workdir.
set -u
cd "$(dirname "$0")/.."
PY=${PYTHON:-.venv/bin/python}
W=${1:-$HOME/.cache/quantumtrace-bench}
mkdir -p "$W"

sparse() {  # sparse <dir> <repo url> <paths...>
  local d=$1 url=$2; shift 2
  [ -d "$d" ] && return
  git clone -q --depth 1 --filter=blob:none --sparse "$url" "$d" && git -C "$d" sparse-checkout set "$@"
}
full() { [ -d "$1" ] || git clone -q --depth 1 "$2" "$1"; }
run() {  # run <name> <command...>: last lines hold the totals
  echo; echo "=================== $1"
  "${@:2}" 2>&1 | tail -n 8
}

full "$W/BenchmarkJava" https://github.com/OWASP-Benchmark/BenchmarkJava.git
run "OWASP Benchmark (Java)" "$PY" scripts/owasp_benchmark.py "$W/BenchmarkJava"

full "$W/cab" https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git
run "CryptoAPI-Bench" "$PY" scripts/cryptoapi_bench.py "$W/cab"

sparse "$W/sgr" https://github.com/semgrep/semgrep-rules.git python javascript go java
run "Semgrep rules" "$PY" scripts/semgrep_rules_bench.py "$W/sgr"

for r in sonar-java sonar-python SonarJS; do
  p=$("$PY" -c "import sys; sys.path.insert(0, 'scripts'); import sonar_bench; print(sonar_bench.SPARSE['$r'])")
  sparse "$W/sonar/$r" "https://github.com/SonarSource/$r.git" "$p"
done
run "Sonar rule samples" "$PY" scripts/sonar_bench.py "$W/sonar"

full "$W/apache" https://github.com/CryptoAPI-Bench/ApacheCryptoAPI-Bench.git
[ -f "$W/cfr.jar" ] || curl -sSL -o "$W/cfr.jar" https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
run "ApacheCryptoAPI-Bench (held-out)" "$PY" scripts/apache_bench.py "$W/apache" "$W/cfr.jar" "$W/apache_src"

sparse "$W/gosec" https://github.com/securego/gosec.git testutils
run "gosec samples" "$PY" scripts/gosec_bench.py "$W/gosec"

sparse "$W/bandit" https://github.com/PyCQA/bandit.git examples
if [ ! -f "$W/bandit.json" ]; then
  [ -x "$W/banditvenv/bin/bandit" ] || { python3 -m venv "$W/banditvenv" && "$W/banditvenv/bin/pip" -q install bandit; }
  (cd "$W/bandit/examples" && "$W/banditvenv/bin/bandit" -q -f json -o "$W/bandit.json" -r . >/dev/null 2>&1)
fi
run "Bandit examples" "$PY" scripts/bandit_bench.py "$W/bandit/examples" "$W/bandit.json"

sparse "$W/codeql" https://github.com/github/codeql.git \
  java/ql/test/query-tests/security/CWE-326 java/ql/test/query-tests/security/CWE-327 java/ql/test/query-tests/security/CWE-338 \
  go/ql/test/query-tests/Security/CWE-326 go/ql/test/query-tests/Security/CWE-327 go/ql/test/query-tests/Security/CWE-338 \
  javascript/ql/test/query-tests/Security/CWE-326 javascript/ql/test/query-tests/Security/CWE-327 \
  javascript/ql/test/query-tests/Security/CWE-338 javascript/ql/test/query-tests/Security/CWE-916 python/ql/test/query-tests/Security
run "CodeQL query tests" "$PY" scripts/codeql_bench.py "$W/codeql"
