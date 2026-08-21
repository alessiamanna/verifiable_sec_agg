#!/usr/bin/env python3
"""Download and verify the OrganAMNIST npz used by fl_heversa.py."""

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


FILENAME = "organamnist.npz"
URL = "https://zenodo.org/records/10519652/files/organamnist.npz?download=1"
MD5 = "68e3f8846a6bd62f0c9bf841c0d9eacc"


def repo_root():
    return Path(__file__).resolve().parents[1]


def default_output_path():
    return repo_root() / ".keras" / "medmnist" / FILENAME


def file_md5(path):
    digest = hashlib.md5()
    with Path(path).open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_existing(path, expected_md5):
    if not path.exists():
        return False

    actual_md5 = file_md5(path)
    if actual_md5 == expected_md5:
        print(f"{path} already exists and MD5 is correct.")
        return True

    raise RuntimeError(
        f"{path} already exists but MD5 is {actual_md5}; expected {expected_md5}. "
        "Rerun with --force to replace it."
    )


def print_progress(downloaded, total):
    downloaded_mb = downloaded / (1024 * 1024)
    if total:
        total_mb = total / (1024 * 1024)
        percent = downloaded * 100 / total
        message = f"\rDownloaded {downloaded_mb:.1f}/{total_mb:.1f} MiB ({percent:.1f}%)"
    else:
        message = f"\rDownloaded {downloaded_mb:.1f} MiB"
    print(message, end="", file=sys.stderr, flush=True)


def download(url, output_path, expected_md5, force):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_path.exists() and not force:
        return verify_existing(output_path, expected_md5)

    tmp_path = output_path.with_name(f".{output_path.name}.tmp-{os.getpid()}")
    try:
        print(f"Downloading {url}")
        print(f"Saving to {output_path}")
        request = urllib.request.Request(url, headers={"User-Agent": "Python"})
        with urllib.request.urlopen(request, timeout=60) as response:
            total = int(response.headers.get("Content-Length") or 0)
            downloaded = 0
            with tmp_path.open("wb") as file_obj:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    file_obj.write(chunk)
                    downloaded += len(chunk)
                    print_progress(downloaded, total)
        print(file=sys.stderr)

        actual_md5 = file_md5(tmp_path)
        if actual_md5 != expected_md5:
            raise RuntimeError(
                f"Downloaded file MD5 is {actual_md5}; expected {expected_md5}."
            )

        os.replace(tmp_path, output_path)
        print(f"Downloaded and verified {output_path}")
        return True
    except (OSError, urllib.error.URLError, RuntimeError):
        tmp_path.unlink(missing_ok=True)
        raise


def parse_args():
    parser = argparse.ArgumentParser(
        description="Download OrganAMNIST into the repo-local cache."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output_path(),
        help="Destination npz path. Defaults to .keras/medmnist/organamnist.npz.",
    )
    parser.add_argument("--url", default=URL, help="Dataset URL.")
    parser.add_argument("--md5", default=MD5, help="Expected MD5 checksum.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing file instead of only verifying it.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        download(args.url, args.output, args.md5, args.force)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
