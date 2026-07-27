#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import argparse
import os
import re
import subprocess
import time
from datetime import datetime
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from plan import PROJECT_DIR
from plan import Package
from plan import plan
from trusted_publishing import temporary_trusted_publishing_token


def parse_retry_after(output: str) -> int:
    match = re.search(r"Please try again after ([^\n]+)", output)
    if match:
        value = match.group(1).strip().rstrip(".")
        for parser in (
            lambda text: parsedate_to_datetime(text),
            lambda text: datetime.fromisoformat(text.replace("Z", "+00:00")),
        ):
            try:
                retry_at = parser(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return max(
                    60,
                    int((retry_at - datetime.now(timezone.utc)).total_seconds()) + 8,
                )
            except ValueError:
                continue
    return 610


def should_retry(output: str) -> bool:
    lowered = output.lower()
    return (
        "too many requests" in lowered
        or "rate limit" in lowered
        or "you have published too many crates" in lowered
    )


def already_published(output: str, package: Package) -> bool:
    lowered = output.lower()
    identity = f"{package.name}@{package.version}".lower()
    return identity in lowered and (
        "already exists" in lowered or "already uploaded" in lowered
    )


def publish_package(project_dir: Path, package: Package) -> str:
    command = [
        "cargo",
        "publish",
        "--package",
        package.name,
        "--no-verify",
    ]

    while True:
        print(f"Publishing {package.name} {package.version}", flush=True)
        with temporary_trusted_publishing_token() as token:
            env = os.environ.copy()
            env["CARGO_REGISTRY_TOKEN"] = token
            process = subprocess.run(
                command,
                cwd=project_dir,
                check=False,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = process.stdout or ""
            print(output, end="", flush=True)

        if process.returncode == 0:
            return "published"
        if already_published(output, package):
            print(
                f"Skipping {package.name} {package.version}: already published",
                flush=True,
            )
            return "already published"
        if should_retry(output):
            delay = parse_retry_after(output)
            print(
                f"crates.io rate limited {package.name}; sleeping {delay}s",
                flush=True,
            )
            time.sleep(delay)
            continue
        raise subprocess.CalledProcessError(process.returncode, command, output=output)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish reqsign crates with fresh OIDC credentials."
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=PROJECT_DIR,
        help="Path to the repository root.",
    )
    args = parser.parse_args()
    project_dir = args.project_dir.resolve()

    results: list[tuple[Package, str]] = []
    for package in plan(project_dir):
        results.append((package, publish_package(project_dir, package)))

    print("Publish plan completed:", flush=True)
    for package, result in results:
        print(f"- {package.name} {package.version}: {result}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
