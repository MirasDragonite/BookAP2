FROM golang:latest

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o comicservice ./server

ENV DB_HOST="host.docker.internal"
ENV DB_PORT="5432"
ENV DB_USER="postgres"
ENV DB_PASSWORD="7151"
ENV DB_NAME="bookstore"

EXPOSE 8080

CMD ["./comicservice"]
