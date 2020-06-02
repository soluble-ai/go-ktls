#!/bin/bash

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
      -E whitespace -E goprintffuncname \
      -e G402 ; # we turn off TLS verification by option
else
    echo "golangci-lint not available, skipping lint"
fi