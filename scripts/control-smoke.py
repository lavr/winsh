"""Exercise the real winsh ControlMaster child against synthetic pyspnego."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


parser = argparse.ArgumentParser(description="Synthetic ControlMaster NTLM smoke test")
parser.add_argument("--binary", default="dist/winsh")
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
fixture_path = Path(__file__).with_name("ntlm-persistent-fixture.py")
fixture = subprocess.Popen(
    [sys.executable, str(fixture_path)],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
endpoint = fixture.stdout.readline().strip()
if not endpoint.startswith("http://127.0.0.1:"):
    raise RuntimeError("synthetic NTLM fixture did not start")

environment = os.environ.copy()
environment.pop("WINSH_CONFIG", None)
environment.pop("WINSH_MISSING_TEST_PASSWORD", None)
base = ["--endpoint", endpoint, "--user", "EXAMPLE\\alice", "--control-persist=1m"]
with tempfile.TemporaryDirectory(prefix="winsh-control-smoke-") as workdir:
    def call(*parts, input_text=None):
        return subprocess.run(
            [binary, *parts],
            input=input_text,
            text=True,
            capture_output=True,
            cwd=workdir,
            env=environment,
            timeout=15,
            check=False,
        )

    try:
        first = call("run", *base, "--control=auto", "--password-stdin", "--", "echo hi", input_text="test-secret\n")
        assert (first.returncode, first.stdout, first.stderr) == (7, "ok\n", "err\n"), (first.returncode, first.stdout, first.stderr)

        second = call("ps", *base, "--control=auto", "--password-env", "WINSH_MISSING_TEST_PASSWORD", "--", "Write-Output 'hi'; exit 7")
        assert (second.returncode, second.stdout, second.stderr) == (7, "ok\n", "err\n"), (second.returncode, second.stdout, second.stderr)

        check = call("control", "check", *base)
        assert check.returncode == 0, (check.returncode, check.stderr)
        with urllib.request.urlopen(endpoint.removesuffix("/wsman") + "/stats", timeout=3) as response:
            counts = json.load(response)
        assert counts == [0, 12], counts

        shutdown = call("control", "exit", *base)
        assert shutdown.returncode == 0, (shutdown.returncode, shutdown.stderr)
        absent = call("control", "check", *base)
        assert absent.returncode == 202, (absent.returncode, absent.stderr)
        print("PASS: two CLI commands reused one NTLM command connection; check/exit removed the master")
    finally:
        call("control", "exit", *base)
        fixture.stdin.write("\n")
        fixture.stdin.flush()
        try:
            fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()
            fixture.wait()
