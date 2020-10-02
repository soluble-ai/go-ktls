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

FROM golang:1.14-buster as build

RUN wget -O - -q https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s v1.31.0

WORKDIR /go/src/app

# run this in a separate step to cache modules between builds
COPY go.mod go.sum ./
RUN go mod download

ADD . /go/src/app

RUN go build -o /go/bin/ktls cmd/ktls/main.go

# copy the executable to distroless
FROM gcr.io/distroless/base-debian10
COPY --from=build /go/bin/ktls /
ENTRYPOINT [ "/ktls" ]