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
import heapq
import json
import subprocess
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
PROJECT_DIR = SCRIPT_PATH.parents[3]


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    path: str


def load_metadata(project_dir: Path = PROJECT_DIR) -> dict[str, object]:
    process = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=project_dir,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    metadata = json.loads(process.stdout)
    if not isinstance(metadata, dict):
        raise RuntimeError("cargo metadata returned an invalid document")
    return metadata


def is_publishable(package: dict[str, object]) -> bool:
    publish = package.get("publish")
    if publish is None:
        return True
    if not isinstance(publish, list):
        raise RuntimeError(
            f"cargo metadata returned invalid publish settings for {package.get('name')}"
        )
    return "crates-io" in publish


def plan_from_metadata(metadata: dict[str, object], project_dir: Path) -> list[Package]:
    raw_packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(raw_packages, list) or not isinstance(workspace_members, list):
        raise RuntimeError("cargo metadata omitted packages or workspace members")

    members = set(workspace_members)
    packages_by_id: dict[str, dict[str, object]] = {}
    publishable_by_dir: dict[Path, dict[str, object]] = {}
    local_by_dir: dict[Path, dict[str, object]] = {}

    for package in raw_packages:
        if not isinstance(package, dict):
            raise RuntimeError("cargo metadata returned an invalid package")
        package_id = package.get("id")
        manifest_path = package.get("manifest_path")
        if not isinstance(package_id, str) or not isinstance(manifest_path, str):
            raise RuntimeError("cargo metadata returned an invalid package identity")
        if package_id not in members:
            continue

        manifest_dir = Path(manifest_path).resolve().parent
        packages_by_id[package_id] = package
        local_by_dir[manifest_dir] = package
        if is_publishable(package):
            publishable_by_dir[manifest_dir] = package

    if set(packages_by_id) != members:
        missing = sorted(members - set(packages_by_id))
        raise RuntimeError(f"cargo metadata omitted workspace packages: {missing}")

    graph: dict[Path, set[Path]] = {
        manifest_dir: set() for manifest_dir in publishable_by_dir
    }
    indegree = {manifest_dir: 0 for manifest_dir in publishable_by_dir}

    for manifest_dir, package in publishable_by_dir.items():
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            raise RuntimeError(
                f"cargo metadata omitted dependencies for {package.get('name')}"
            )

        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise RuntimeError("cargo metadata returned an invalid dependency")
            if dependency.get("kind") == "dev":
                continue
            dependency_path = dependency.get("path")
            if not isinstance(dependency_path, str):
                continue

            dependency_dir = Path(dependency_path).resolve()
            if dependency_dir not in local_by_dir:
                continue
            if dependency_dir not in publishable_by_dir:
                raise RuntimeError(
                    f"{package.get('name')} depends on unpublished workspace package "
                    f"{local_by_dir[dependency_dir].get('name')}"
                )
            if manifest_dir in graph[dependency_dir]:
                continue

            graph[dependency_dir].add(manifest_dir)
            indegree[manifest_dir] += 1

    queue = [
        (manifest_dir.relative_to(project_dir).as_posix(), manifest_dir)
        for manifest_dir, degree in indegree.items()
        if degree == 0
    ]
    heapq.heapify(queue)

    ordered: list[Package] = []
    while queue:
        _, manifest_dir = heapq.heappop(queue)
        package = publishable_by_dir[manifest_dir]
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise RuntimeError("cargo metadata returned invalid package metadata")

        ordered.append(
            Package(
                name=name,
                version=version,
                path=manifest_dir.relative_to(project_dir).as_posix(),
            )
        )
        for dependent in graph[manifest_dir]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(
                    queue,
                    (dependent.relative_to(project_dir).as_posix(), dependent),
                )

    if len(ordered) != len(publishable_by_dir):
        cyclic = sorted(
            publishable_by_dir[path].get("name")
            for path, degree in indegree.items()
            if degree > 0
        )
        raise RuntimeError(f"publishable workspace dependency cycle: {cyclic}")

    names = [package.name for package in ordered]
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate crates.io package name in publish plan")
    return ordered


def plan(project_dir: Path = PROJECT_DIR) -> list[Package]:
    project_dir = project_dir.resolve()
    return plan_from_metadata(load_metadata(project_dir), project_dir)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print the reqsign crates.io publish plan in dependency order."
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=PROJECT_DIR,
        help="Path to the repository root.",
    )
    args = parser.parse_args()
    print(json.dumps([asdict(package) for package in plan(args.project_dir)], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
