FROM golang:1.18-alpine3.16 AS builder
WORKDIR /app
COPY . .
RUN go build -o main main.go

EXPOSE 8080

FROM alpine:3.16 
WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/app.env .
CMD ["/app/main"]  