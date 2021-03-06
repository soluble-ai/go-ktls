#!/bin/bash
# Copyright 2020 Soluble Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


set -e

echo "Running go test"
go test -cover ./...

linter=golangci-lint
if [ -x ./bin/golangci-lint ]; then
    linter=./bin/golangci-lint
fi

if "${linter}" --help > /dev/null 2>&1; then
    echo "Running ${linter}"
    "${linter}" run -E stylecheck -E gosec -E goimports -E misspell -E gocritic \
      -E whitespace -E goprintffuncname
else
    echo "golangci-lint not available, skipping lint"
fi

go build -o ktls cmd/ktls/main.go
