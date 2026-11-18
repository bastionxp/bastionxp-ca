# Copyright 2026 Ampas Labs Inc.
# SPDX-License-Identifier: Apache-2.0

# BastionXP CA in a container: one static binary on a distroless base, running
# as a non-root user.
#
#   docker build -t bastionxp-ca .
#
# See "Run in a container" in the BastionXP CA documentation.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# The commit and its date (RFC 3339): .git is not copied in, so Go cannot
# record them by itself. "bxp --version" shows them.
ARG COMMIT=
ARG COMMIT_TIME=
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The SQLite driver is pure Go, so no C compiler is needed and the binary
# runs anywhere.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.commitTime=${COMMIT_TIME}" -o /out/bxp ./cmd/bxp \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bxp /usr/local/bin/bxp
# The data directory belongs to the user the server runs as.
COPY --from=build --chown=65532:65532 /out/data /var/lib/bastionxp-ca
USER 65532:65532
VOLUME ["/var/lib/bastionxp-ca"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/bxp"]
CMD ["serve", "--config", "/etc/bastionxp-ca/bastionxp-ca.yaml"]
