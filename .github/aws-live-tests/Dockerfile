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

FROM public.ecr.aws/docker/library/rust:1.88-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo test -p reqsign-aws-v4 --test main --release --no-run && \
    test_binary="$(find target/release/deps -maxdepth 1 -type f -perm -111 -name 'main-*' | head -n 1)" && \
    test -n "${test_binary}" && \
    cp "${test_binary}" /tmp/reqsign-aws-live-test

FROM public.ecr.aws/docker/library/debian:bookworm-slim

RUN apt-get update && \
    apt-get install --yes --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /tmp/reqsign-aws-live-test /usr/local/bin/reqsign-aws-live-test

ENTRYPOINT ["/usr/local/bin/reqsign-aws-live-test"]
