# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build
COPY go.mod .
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o ifrit ./cmd/ifrit

# Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /build/ifrit .
COPY config/ ./config/

EXPOSE 8080 8443

CMD ["./ifrit"]
