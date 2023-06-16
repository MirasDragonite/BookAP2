# Use an official Golang runtime as the base image
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the necessary files to the working directory
COPY go.mod .
COPY go.sum .
# Download the dependencies
RUN go mod download

# Copy the project code to the working directory
COPY . .
RUN go mod tidy
# Build the application
RUN go build -o bookservice ./server

# Set the required environment variables
ENV DB_HOST="host.docker.internal"
ENV DB_PORT="5432"
ENV DB_USER="postgres"
ENV DB_PASSWORD="7151"
ENV DB_NAME="bookstore"
# Expose the application port
EXPOSE 8081

# Set the default command to run your application
CMD ["./bookservice"]
