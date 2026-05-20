FROM golang:1.25-alpine AS builder
ARG CMMD
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN test -n "${CMMD}" && \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /app ./cmd/${CMMD}

FROM scratch
COPY --from=builder /app /app
ENTRYPOINT ["/app"]