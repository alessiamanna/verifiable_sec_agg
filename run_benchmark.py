#!/usr/bin/env python3
"""
HeVerSa Ultra96-V2 Benchmark Runner Tool
========================================
Runs the pre-compiled HeVerSa benchmark binary on the Avnet Ultra96-V2 board
(or locally if executed on the board) WITHOUT recompiling each time, allowing
you to customize:
  - Model update length (--update-len / -m), single or comma-separated list
  - Dropout percentage (--dropout-pct / -d), single or comma-separated list
  - Client count or sweep (--clients / -n, or --min-clients / --max-clients / --step-clients)
  - Number of iterations (--iterations / -i)
  - Topology (--topology log2 | log2_sq | complete)

Automatically downloads the resulting summary and raw CSV files to your PC.

Examples:
  # 1. Single update_len (M=256) and 20% dropouts across N=50..500:
  python run_benchmark.py -m 256 -d 20

  # 2. Sweep multiple dropout percentages (0%, 10%, 20%, 30%) at M=256 (Thesis Fig. 5.1):
  python run_benchmark.py -m 256 -d 0,10,20,30

  # 3. Sweep multiple update lengths (M=16..1024) at fixed N=500 (Thesis Fig. 5.2):
  python run_benchmark.py -n 500 -m 16,32,64,128,256,512,1024 -d 0,10,20,30

  # 4. Interactive prompt mode:
  python run_benchmark.py --interactive
"""

import argparse
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_HOST = "192.168.3.1"
DEFAULT_USER = "xilinx"
DEFAULT_PASS = "xilinx"
REMOTE_DIR = "/tmp/heversa_bench"
REMOTE_BIN = f"{REMOTE_DIR}/build/benchmark"


def is_running_on_ultra96() -> bool:
    """Detect if this script is already executing on the Ultra96-V2 Linux board."""
    return platform.system().lower() == "linux" and platform.machine().lower() in ("aarch64", "arm64")


def make_ssh_env(password: str):
    """Create a temporary SSH_ASKPASS helper script for non-interactive OpenSSH."""
    tmp_dir = tempfile.mkdtemp(prefix="heversa_ssh_")
    if os.name == "nt":
        askpass_path = os.path.join(tmp_dir, "askpass.bat")
        with open(askpass_path, "w", encoding="utf-8") as f:
            f.write(f"@echo {password}\n")
    else:
        askpass_path = os.path.join(tmp_dir, "askpass.sh")
        with open(askpass_path, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/sh\necho '{password}'\n")
        os.chmod(askpass_path, 0o700)

    env = os.environ.copy()
    env["SSH_ASKPASS"] = askpass_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    if "DISPLAY" not in env or not env["DISPLAY"]:
        env["DISPLAY"] = "dummy:0"
    return env, tmp_dir


def cleanup_ssh_env(tmp_dir: str):
    try:
        for root, _, files in os.walk(tmp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
        os.rmdir(tmp_dir)
    except OSError:
        pass


def run_ssh_cmd(host: str, user: str, env: dict, remote_cmd: str, stream_output: bool = True) -> int:
    ssh_args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{user}@{host}",
        remote_cmd,
    ]
    if stream_output:
        proc = subprocess.run(ssh_args, env=env)
        return proc.returncode
    else:
        proc = subprocess.run(ssh_args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.returncode


def scp_to_board(host: str, user: str, env: dict, local_paths: list[str], remote_dest: str) -> int:
    scp_args = [
        "scp",
        "-r",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        *local_paths,
        f"{user}@{host}:{remote_dest}",
    ]
    return subprocess.run(scp_args, env=env).returncode


def scp_from_board(host: str, user: str, env: dict, remote_src: str, local_dest: str) -> int:
    scp_args = [
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        f"{user}@{host}:{remote_src}",
        local_dest,
    ]
    return subprocess.run(scp_args, env=env).returncode


def prompt_interactive(args: argparse.Namespace):
    print("==================================================================")
    print("  HeVerSa Interactive Benchmark Configuration (Ultra96-V2)")
    print("==================================================================")

    m_in = input(f"  Update length M (single or comma-separated) [{args.update_len}]: ").strip()
    if m_in:
        args.update_len = m_in

    d_in = input(
        f"  Dropout percentage (e.g. 0, 10, 20 or 0,10,20,30) [{args.dropout_pct or '0'}]: "
    ).strip()
    if d_in:
        args.dropout_pct = d_in
    elif not args.dropout_pct and args.dropout_ratio is None:
        args.dropout_pct = "0"

    n_mode = input("  Client mode - (1) Sweep 50..500 or (2) Single client count N [1]: ").strip()
    if n_mode == "2":
        n_val = input("    Enter client count N [500]: ").strip()
        args.clients = int(n_val) if n_val else 500
    else:
        min_n = input(f"    Min clients [{args.min_clients}]: ").strip()
        max_n = input(f"    Max clients [{args.max_clients}]: ").strip()
        step_n = input(f"    Step clients [{args.step_clients}]: ").strip()
        if min_n:
            args.min_clients = int(min_n)
        if max_n:
            args.max_clients = int(max_n)
        if step_n:
            args.step_clients = int(step_n)

    it_in = input(f"  Iterations per configuration [{args.iterations}]: ").strip()
    if it_in:
        args.iterations = int(it_in)

    sum_in = input(f"  Summary CSV output filename [{args.summary_csv}]: ").strip()
    if sum_in:
        args.summary_csv = sum_in

    raw_in = input(f"  Raw CSV output filename [{args.raw_csv}]: ").strip()
    if raw_in:
        args.raw_csv = raw_in
    print("==================================================================\n")


def build_benchmark_cli_args(args: argparse.Namespace, remote_raw_csv: str, remote_sum_csv: str) -> list[str]:
    cli = [
        "--update-len", str(args.update_len),
        "--iterations", str(args.iterations),
        "--topology", str(args.topology),
        "--c-factor", str(args.c_factor),
        "--threshold-ratio", str(args.threshold_ratio),
        "--raw-csv", remote_raw_csv,
        "--summary-csv", remote_sum_csv,
    ]
    if args.clients is not None:
        cli += ["--clients", str(args.clients)]
    else:
        cli += [
            "--min-clients", str(args.min_clients),
            "--max-clients", str(args.max_clients),
            "--step-clients", str(args.step_clients),
        ]

    if args.dropout_pct is not None:
        cli += ["--dropout-pct", str(args.dropout_pct)]
    elif args.dropout_ratio is not None:
        cli += ["--dropout-ratio", str(args.dropout_ratio)]
    else:
        cli += ["--dropouts", str(args.dropouts)]

    if args.degree > 0:
        cli += ["--degree", str(args.degree)]
    if args.threshold > 0:
        cli += ["--threshold", str(args.threshold)]
    if args.no_pollute:
        cli.append("--no-pollute")

    return cli


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run HeVerSa single-node benchmark on Avnet Ultra96-V2 without recompiling."
    )
    parser.add_argument(
        "-m", "--update-len",
        default="1024",
        help="Model update vector length M, or comma-separated list e.g. '16,32,64,128,256,1024' (default: 1024)"
    )
    parser.add_argument(
        "-d", "--dropout-pct",
        default=None,
        help="Dropout percentage in [0,100), or comma-separated list e.g. '0,10,20,30' (default: 0)"
    )
    parser.add_argument(
        "--dropout-ratio",
        default=None,
        help="Dropout fraction in [0,1), or comma-separated list e.g. '0,0.1,0.2,0.3'"
    )
    parser.add_argument(
        "--dropouts",
        type=int,
        default=0,
        help="Fixed number of dropped clients if --dropout-pct is not set (default: 0)"
    )
    parser.add_argument(
        "-n", "--clients",
        type=int,
        default=None,
        help="Run for a single client count N (overrides --min/max/step-clients)"
    )
    parser.add_argument("--min-clients", type=int, default=50, help="Min clients in sweep (default: 50)")
    parser.add_argument("--max-clients", type=int, default=500, help="Max clients in sweep (default: 500)")
    parser.add_argument("--step-clients", type=int, default=50, help="Client sweep step size (default: 50)")
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=30,
        help="Iterations per configuration point (default: 30)"
    )
    parser.add_argument(
        "--topology",
        choices=["log2", "log2_sq", "complete"],
        default="log2",
        help="Recovery graph topology (default: log2 = Bell et al. Harary graph)"
    )
    parser.add_argument("--c-factor", type=float, default=6.0, help="Scaling factor c in ceil(c*log2(N)) (default: 6.0)")
    parser.add_argument("--degree", type=int, default=0, help="Override fixed neighbor degree |K_j|")
    parser.add_argument("--threshold", type=int, default=0, help="Override fixed Shamir threshold K")
    parser.add_argument("--threshold-ratio", type=float, default=0.5, help="Threshold ratio of degree (default: 0.5)")
    parser.add_argument("--no-pollute", action="store_true", help="Disable 2 MB L2 cache pollution between rounds")
    parser.add_argument(
        "--summary-csv",
        default="ultra96_benchmark_summary.csv",
        help="Output filename for summary CSV (default: ultra96_benchmark_summary.csv)"
    )
    parser.add_argument(
        "--raw-csv",
        default="ultra96_benchmark_raw.csv",
        help="Output filename for raw per-iteration CSV (default: ultra96_benchmark_raw.csv)"
    )
    parser.add_argument("-I", "--interactive", action="store_true", help="Prompt interactively for parameters")
    parser.add_argument("--rebuild", action="store_true", help="Force uploading source files and recompiling on board")
    parser.add_argument("--local", action="store_true", help="Run ./build/benchmark locally instead of via SSH")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Ultra96-V2 IP/hostname (default: {DEFAULT_HOST})")
    parser.add_argument("--user", default=DEFAULT_USER, help=f"Ultra96-V2 SSH username (default: {DEFAULT_USER})")
    parser.add_argument("--password", default=DEFAULT_PASS, help=f"Ultra96-V2 SSH password (default: {DEFAULT_PASS})")

    args = parser.parse_args()

    if args.interactive:
        prompt_interactive(args)

    # Local execution path (if running directly on the Ultra96-V2 board or with --local)
    if args.local or is_running_on_ultra96():
        local_bin = Path("build/benchmark")
        if args.rebuild or not local_bin.exists():
            print("[INFO] Building benchmark binary locally...")
            rc = subprocess.run(["bash", "build_ultra96.sh"]).returncode
            if rc != 0:
                print("[ERROR] Build failed.", file=sys.stderr)
                return rc
        cli_args = build_benchmark_cli_args(args, args.raw_csv, args.summary_csv)
        cmd = [str(local_bin), *cli_args]
        print(f"[INFO] Running locally: {' '.join(cmd)}\n")
        return subprocess.run(cmd).returncode

    # Remote execution path over SSH to Ultra96-V2
    env, tmp_dir = make_ssh_env(args.password)
    try:
        # 1. Check if pre-compiled binary already exists on the board
        need_build = args.rebuild
        if not need_build:
            check_rc = run_ssh_cmd(
                args.host, args.user, env,
                f"test -x {REMOTE_BIN}",
                stream_output=False
            )
            if check_rc != 0:
                print(f"[INFO] Binary {REMOTE_BIN} not found on board (e.g. after reboot). Building once...")
                need_build = True

        if need_build:
            print(f"[INFO] Uploading source files to {args.user}@{args.host}:{REMOTE_DIR} ...")
            run_ssh_cmd(args.host, args.user, env, f"mkdir -p {REMOTE_DIR}", stream_output=False)
            if scp_to_board(args.host, args.user, env, ["src", "build_ultra96.sh"], f"{REMOTE_DIR}/") != 0:
                print("[ERROR] Failed to upload source files via SCP.", file=sys.stderr)
                return 1
            build_cmd = f"cd {REMOTE_DIR} && sed -i 's/\\r$//' build_ultra96.sh && bash build_ultra96.sh"
            if run_ssh_cmd(args.host, args.user, env, build_cmd, stream_output=True) != 0:
                print("[ERROR] Remote compilation failed on Ultra96-V2.", file=sys.stderr)
                return 1

        # 2. Run the pre-compiled binary on the Ultra96-V2 with the requested runtime flags
        remote_raw = f"{REMOTE_DIR}/ultra96_run_raw.csv"
        remote_sum = f"{REMOTE_DIR}/ultra96_run_summary.csv"
        cli_args = build_benchmark_cli_args(args, remote_raw, remote_sum)
        quoted_args = " ".join(f"'{a}'" for a in cli_args)
        run_cmd = f"cd {REMOTE_DIR} && {REMOTE_BIN} {quoted_args}"

        print(f"[INFO] Executing pre-compiled benchmark on Ultra96-V2 ({args.host}) [NO RECOMPILATION]:")
        print(f"       {REMOTE_BIN} {' '.join(cli_args)}\n")

        rc = run_ssh_cmd(args.host, args.user, env, run_cmd, stream_output=True)
        if rc != 0:
            print(f"[ERROR] Benchmark exited with code {rc}.", file=sys.stderr)
            return rc

        # 3. Download the CSV files to the local PC
        print(f"\n[INFO] Downloading CSV results from Ultra96-V2 to local PC...")
        if scp_from_board(args.host, args.user, env, remote_sum, args.summary_csv) == 0:
            print(f"  -> Saved summary CSV : {os.path.abspath(args.summary_csv)}")
        else:
            print("[WARNING] Could not download summary CSV.", file=sys.stderr)

        if scp_from_board(args.host, args.user, env, remote_raw, args.raw_csv) == 0:
            print(f"  -> Saved raw CSV     : {os.path.abspath(args.raw_csv)}")
        else:
            print("[WARNING] Could not download raw CSV.", file=sys.stderr)

        return 0
    finally:
        cleanup_ssh_env(tmp_dir)


if __name__ == "__main__":
    sys.exit(main())
