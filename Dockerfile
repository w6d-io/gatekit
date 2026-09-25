# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gatekit ./cmd/gatekit

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gatekit /gatekit
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/gatekit"]
