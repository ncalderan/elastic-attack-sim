# script_runner.py
import os
import subprocess
import sys
from typing import Dict, Iterator

def run_generator(script_path: str, args: Dict[str, object]) -> Iterator[str]:
    """
    Runs the generator as a subprocess and streams logs line-by-line.
    - Converts arg names like batch_size -> batch-size for CLI
    - Emits boolean flags (e.g., --dry-run) when value is True
    """
    cmd = [sys.executable, script_path]

    for k, v in args.items():
        if v is None:
            continue
        cli_key = k.replace("_", "-")  # <-- normalize to hyphenated CLI
        if isinstance(v, bool):
            if v:  # only include true flags
                cmd.append(f"--{cli_key}")
        else:
            cmd += [f"--{cli_key}", str(v)]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=os.environ.copy(),
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    if proc.stdout:
        for line in proc.stdout:
            yield line.rstrip()

    proc.wait()
