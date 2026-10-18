# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the Secrets Bridge Gateway. The runtime image is
# distroless/static: no shell, no package manager, runs as nonroot. The
# Gateway listens on loopback only, so the image exposes no port.

FROM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.buildVersion=${BUILD_VERSION}" \
      -o /out/gateway \
      ./cmd/gateway

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/gateway /usr/local/bin/gateway
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gateway"]
