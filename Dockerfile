FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o gophkeeper-server ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/gophkeeper-server .
COPY configs/config.yaml ./config.yaml
EXPOSE 8080
CMD ["./gophkeeper-server", "-config", "./config.yaml"]