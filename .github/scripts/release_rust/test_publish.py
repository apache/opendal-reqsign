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

import subprocess
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from plan import Package
from publish import already_published
from publish import publish_package


def subprocess_result(returncode: int, output: str):
    return mock.Mock(returncode=returncode, stdout=output)


class ReleaseRustPublishTest(unittest.TestCase):
    def test_live_publish_fetches_a_new_token_for_every_attempt(self):
        package = Package("reqsign-test", "1.0.0", "test")
        tokens = iter(("first-token", "second-token"))
        revoked: list[str] = []
        cargo_tokens: list[str | None] = []
        cargo_commands: list[list[str]] = []

        @contextmanager
        def token_provider():
            token = next(tokens)
            try:
                yield token
            finally:
                revoked.append(token)

        results = iter(
            (
                subprocess_result(
                    1, "Too many requests. Please try again after invalid."
                ),
                subprocess_result(0, "published"),
            )
        )

        def run(*args, **kwargs):
            cargo_commands.append(args[0])
            cargo_tokens.append(kwargs["env"].get("CARGO_REGISTRY_TOKEN"))
            return next(results)

        with (
            mock.patch.dict(
                "publish.os.environ",
                {"CARGO_REGISTRY_TOKEN": "legacy-token"},
                clear=True,
            ),
            mock.patch("publish.temporary_trusted_publishing_token", token_provider),
            mock.patch("publish.subprocess.run", run),
            mock.patch("publish.time.sleep") as sleep,
        ):
            result = publish_package(Path(), package)

        self.assertEqual(result, "published")
        self.assertEqual(
            cargo_commands,
            [
                [
                    "cargo",
                    "publish",
                    "--package",
                    "reqsign-test",
                    "--no-verify",
                ],
                [
                    "cargo",
                    "publish",
                    "--package",
                    "reqsign-test",
                    "--no-verify",
                ],
            ],
        )
        self.assertEqual(cargo_tokens, ["first-token", "second-token"])
        self.assertEqual(revoked, ["first-token", "second-token"])
        sleep.assert_called_once_with(610)

    def test_already_published_package_is_recoverable(self):
        package = Package("reqsign-test", "1.0.0", "test")

        @contextmanager
        def token_provider():
            yield "temporary-token"

        with (
            mock.patch("publish.temporary_trusted_publishing_token", token_provider),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(
                    101,
                    "error: crate reqsign-test@1.0.0 already exists on crates.io index",
                ),
            ),
        ):
            result = publish_package(Path(), package)

        self.assertEqual(result, "already published")

    def test_unrelated_already_exists_error_is_not_ignored(self):
        package = Package("reqsign-test", "1.0.0", "test")
        self.assertFalse(
            already_published(
                "crate another@1.0.0 already exists on crates.io index", package
            )
        )

    def test_non_retryable_failure_is_reported(self):
        package = Package("reqsign-test", "1.0.0", "test")

        @contextmanager
        def token_provider():
            yield "temporary-token"

        with (
            mock.patch("publish.temporary_trusted_publishing_token", token_provider),
            mock.patch(
                "publish.subprocess.run",
                return_value=subprocess_result(101, "permission denied"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            publish_package(Path(), package)


if __name__ == "__main__":
    unittest.main()
