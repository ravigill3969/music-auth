FROM golang:1.25-alpine AS build

WORKDIR /app
COPY . .

RUN go mod tidy
RUN go build -o auth-service .

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/auth-service .
EXPOSE 8081

CMD ["./auth-service"]
