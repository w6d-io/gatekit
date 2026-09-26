# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/gatekit ./cmd/gatekit

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gatekit /gatekit
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/gatekit"]
