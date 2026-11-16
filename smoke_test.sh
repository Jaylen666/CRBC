#!/usr/bin/env bash
# Offline CRBC self-check. All generated files remain in a temporary directory.
# Usage: PYTHON=/path/to/python3 bash /path/to/CRBC/smoke_test.sh
set -euo pipefail

CRBC_PACKAGE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CRBC_SMOKE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/crbc-smoke.XXXXXXXX")"
trap 'rm -rf -- "${CRBC_SMOKE_TMP}"' EXIT
export PYTHONDONTWRITEBYTECODE=1

"${PYTHON:-python3}" - "${CRBC_PACKAGE_ROOT}" "${CRBC_SMOKE_TMP}" <<'PY'
import ast
import json
import os
from pathlib import Path
import subprocess
import sys

package = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
passed = 0


def ok(label):
    global passed
    passed += 1
    print(f"[PASS] {label}", flush=True)


def run(label, command):
    completed = subprocess.run(command, cwd=work, env=child_env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        print(f"[FAIL] {label}\n{completed.stdout}", file=sys.stderr)
        raise SystemExit(completed.returncode)
    ok(label)
    return completed.stdout


# Reject accidental network use by Python subprocesses, including model downloads.
(work / "sitecustomize.py").write_text(
    "import socket\n"
    "def _offline(*args, **kwargs):\n"
    "    raise RuntimeError('Network access is disabled during the offline smoke test')\n"
    "socket.create_connection = _offline\n"
    "socket.socket.connect = _offline\n"
    "socket.socket.connect_ex = _offline\n",
    encoding="utf-8",
)
env_file = work / "offline.env"
env_file.write_text("# Offline smoke test; no credentials required.\n", encoding="utf-8")
child_env = os.environ.copy()
for name in list(child_env):
    if name.endswith(("_API_KEY", "_TOKEN")):
        child_env.pop(name)
child_env.update({
    "PYTHONPATH": os.pathsep.join((str(work), str(package))),
    "PYTHONDONTWRITEBYTECODE": "1",
    "ENV_FILE": str(env_file),
    "CRBC_OPENAI_MODEL": "offline-test-model",
    "CRBC_PHASE3_MODEL": "offline-test-model",
    "CRBC_OPENAI_BASE_URL": "https://example.invalid/v1",
    "HF_HOME": str(work / "huggingface"),
    "XDG_CACHE_HOME": str(work / "cache"),
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
    "HF_HUB_DISABLE_TELEMETRY": "1",
})

# Parse source without importing it or producing bytecode. Ignore local venvs.
excluded = {".git", ".venv", "venv", "__pycache__", ".cache", ".pytest_cache"}
sources = []
for directory, dirnames, filenames in os.walk(package):
    dirnames[:] = sorted(name for name in dirnames if name not in excluded)
    sources.extend(Path(directory) / name for name in sorted(filenames))
python_sources = [p for p in sources if p.suffix == ".py"]
for source in python_sources:
    ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
ok(f"Python syntax ({len(python_sources)} files)")
shell_sources = [p for p in sources if p.suffix == ".sh"]
for source in shell_sources:
    run(f"Shell syntax: {source.relative_to(package)}", ["bash", "-n", str(source)])

py = sys.executable
run("CLI help: rtl_bug_agent.cli", [py, "-m", "rtl_bug_agent.cli", "--help"])
for script in ("run_crbc.py", "generate_all_specs.py", "run_phase2_e2e.py", "run_phase3.py"):
    run(f"CLI help: {script}", [py, str(package / "scripts" / script), "--help"])

rtl = work / "rtl"
rtl.mkdir()
source = rtl / "demo.sv"
source.write_text("""module demo (
  input logic clk_i,
  input logic rst_ni,
  input logic enable_i,
  input logic data_i,
  output logic data_o,
  output logic ready_o
);
  assign ready_o = enable_i;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      data_o <= 1'b0;
    end else if (enable_i) begin
      data_o <= data_i;
    end
  end
endmodule
""", encoding="utf-8")
chunks_path = work / "chunks.json"
run("Synthetic RTL chunking", [py, "-m", "rtl_bug_agent.cli", "chunk",
    "--rtl-dir", str(rtl), "--rtl-files", str(source), "--out", str(chunks_path)])
chunks = json.loads(chunks_path.read_text(encoding="utf-8"))
assert chunks and all(chunk.get("chunk_id") for chunk in chunks), "Chunk output is empty or malformed"
ok(f"Synthetic chunk output ({len(chunks)} chunks)")

# dry-run must print its plan without creating the output directory.
dry_output = work / "dry-run-output"
plan = run("CRBC dry-run", [py, str(package / "scripts/run_crbc.py"),
    "--module", "demo", "--repo-root", str(rtl), "--rtl-dir", str(rtl),
    "--out-dir", str(dry_output), "--no-ref", "--env-file", str(env_file),
    "--semantic-hf-home", str(work / "huggingface"), "--dry-run"])
assert not dry_output.exists(), "dry-run unexpectedly created output files"
assert "[chunk]" in plan and "[source review]" in plan, "dry-run omitted pipeline stages"
ok("Dry-run leaves no pipeline outputs")

findings_dir = work / "findings"
findings_dir.mkdir()
finding = {"finding_id": "F-1", "severity": "HIGH", "score": 1.0, "ref_clues": []}
(findings_dir / "findings_demo.json").write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
run_root = work / "review"
run("Phase 3 offline prepare", [py, str(package / "scripts/run_phase3.py"),
    "--repo-root", str(rtl), "--out-root", str(findings_dir), "--run-root", str(run_root),
    "--run-id", "smoke", "--prepare-only", "--env-file", str(env_file),
    "--codex-bin", "not-installed-offline-codex"])
run_dir = run_root / "phase3_runs" / "smoke"
payload = json.loads((run_dir / "demo/inputs/shard_001.json").read_text(encoding="utf-8"))
assert payload["rtl_root"] == str(rtl)
assert len(payload["findings"]) == 1 and payload["findings"][0]["finding_id"] == "F-1"
result_file = json.loads((run_dir / "demo/phase3_results.json").read_text(encoding="utf-8"))
assert result_file["results"] == []
schema = json.loads((package / "config/phase3_schema.json").read_text(encoding="utf-8"))
assert schema["type"] == "object" and schema["required"] == ["results"]
assert schema["properties"]["results"]["type"] == "array"
item = schema["properties"]["results"]["items"]
assert item["type"] == "object" and item["additionalProperties"] is False
assert set(item["required"]) == set(item["properties"])
assert {"finding_id", "finding_hash", "verdict", "source_evidence"}.issubset(item["required"])
ok("Phase 3 prepared input, output, and schema contract")
print(f"CRBC offline smoke test passed ({passed} checks). Temporary files are removed on exit.")
PY
