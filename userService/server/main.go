package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"

	pb "UserService/userserver/test"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

const (
	port           = ":50053"
	smtpServer     = "smtp.office365.com"
	smtpPort       = 587
	smtpUsername   = "211484@astanait.edu.kz"
	smtpPassword   = "Aitu2021!"
	smtpSender     = "211484@astanait.edu.kz"
	smtpSubject    = "Account Activation"
	smtpBodyTmpl   = "Dear user,\r\nPlease use the following activation token to activate your account: %s\r\n\r\nThank you,\r\nYour Application"
	smtpServerName = "smtp.office365.com"
)

type server struct {
	pb.UnimplementedUserServiceServer
	db *sql.DB
}

func (s *server) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	user := req.GetUser()

	var id int32
	var version int32

	stmt := `
		INSERT INTO users (name, email, password_hash, activated, roles, activation_token)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, version
	`

	token, err := generateActivationToken()
	if err != nil {
		return nil, err
	}

	fmt.Println("Pass:", user.GetPassword())
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, stmt,
		user.GetName(), user.GetEmail(), user.GetPassword(), false, user.GetRoles(), token,
	).Scan(&id, &version)
	if err != nil {
		return nil, err
	}

	user.Id = id

	err = sendActivationEmail(user.GetEmail(), token)
	if err != nil {

		return nil, err
	}

	registeredUser := &pb.User{
		Id:        user.Id,
		Name:      user.GetName(),
		Email:     user.GetEmail(),
		Activated: false,
		Roles:     user.GetRoles(),
	}
	return &pb.RegisterUserResponse{
		User: registeredUser,
	}, nil
}

func generateActivationToken() (string, error) {

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	command := string(fromServer)
	command = strings.TrimSpace(command)
	command = strings.TrimSuffix(command, ":")
	command = strings.ToLower(command)

	if more {
		if command == "username" {
			return []byte(fmt.Sprintf("%s", a.username)), nil
		} else if command == "password" {
			return []byte(fmt.Sprintf("%s", a.password)), nil
		} else {
			return nil, fmt.Errorf("unexpected server challenge: %s", command)
		}
	}
	return nil, nil
}

func sendActivationEmail(email, token string) error {

	auth := LoginAuth(smtpUsername, smtpPassword)

	tlsConfig := &tls.Config{
		ServerName: smtpServerName,
	}

	smtpClient, err := smtp.Dial(fmt.Sprintf("%s:%d", smtpServer, smtpPort))
	if err != nil {
		return err
	}
	defer smtpClient.Close()

	err = smtpClient.StartTLS(tlsConfig)
	if err != nil {
		return err
	}

	if err = smtpClient.Auth(auth); err != nil {
		return err
	}

	if err = smtpClient.Mail(smtpSender); err != nil {
		return err
	}
	if err = smtpClient.Rcpt(email); err != nil {
		return err
	}

	message := fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		smtpBodyTmpl, email, smtpSubject, token)

	wc, err := smtpClient.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	_, err = wc.Write([]byte(message))
	if err != nil {
		return err
	}

	return nil
}
func (s *server) ActivateUser(ctx context.Context, req *pb.ActivateUserRequest) (*pb.User, error) {
	activation_token := req.GetActivationCode()

	fmt.Println(req.GetId())

	stmt := `
		UPDATE users
		SET activated = true
		WHERE activation_token = $1
		RETURNING id, name, email, activated, roles
	`

	row := s.db.QueryRowContext(ctx, stmt, activation_token)

	var (
		id    int32
		name  string
		email string

		activated bool
		roles     string
	)

	err := row.Scan(&id, &name, &email, &activated, &roles)
	if err != nil {

		if err == sql.ErrNoRows {
			return nil, status.Errorf(codes.NotFound, "User not found")
		}

		return nil, status.Errorf(codes.Internal, "Failed to activate user: %v", err)
	}

	user := &pb.User{
		Id:        req.GetId(),
		Name:      name,
		Email:     email,
		Activated: true,
		Roles:     roles,
	}

	return user, nil
}

// Авторизация

func (s *server) AuthenticateUser(ctx context.Context, req *pb.AuthenticateUserRequest) (*pb.AuthenticateUserResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()
	stmt := `
	SELECT id, name, email, password_hash, activated, roles
	FROM users
	WHERE email = $1
`

	row := s.db.QueryRowContext(ctx, stmt, email)

	var (
		id        int32
		name      string
		hash      []byte
		activated bool
		roles     string
	)

	err := row.Scan(&id, &name, &email, &hash, &activated, &roles)
	if err != nil {
		if err == sql.ErrNoRows {

			return nil, status.Errorf(codes.NotFound, "Invalid email or password")
		}
		return nil, status.Errorf(codes.Internal, "Failed to fetch user: %v", err)
	}

	fmt.Println("Email checked")

	hashString := hash

	fmt.Println("Retrieved Hashed Password:", hashString)
	fmt.Println("Plain Password:", []byte(password))

	err = comparePasswords(password, []byte(hashString))
	if err != nil {

		return nil, status.Errorf(codes.NotFound, "Password man what")
	}

	fmt.Println("Password checked")

	token, err := generateAuthToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate authentication token: %v", err)
	}

	response := &pb.AuthenticateUserResponse{
		Token: token,
		User: &pb.User{
			Id:        id,
			Name:      name,
			Email:     email,
			Activated: activated,
			Roles:     roles,
		},
	}

	return response, nil
}

func comparePasswords(plainPassword string, hashedPassword []byte) error {

	plainPasswordBytes := []byte(plainPassword)

	match := subtle.ConstantTimeCompare(hashedPassword, plainPasswordBytes)

	if match == 1 {

		return nil
	} else {

		return fmt.Errorf("passwords do not match")
	}
}
func generateAuthToken() (string, error) {

	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	return token, nil
}

func main() {
	host := os.Getenv("DB_HOST")
	portDB := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	// Create a database connection
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portDB, user, password, dbname)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &server{db: db})
	log.Printf("gRPC server listening on %s", port)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	// Create a gRPC-Gateway Mux and register the gRPC server endpoint
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err = pb.RegisterUserServiceHandlerFromEndpoint(context.Background(), mux, fmt.Sprintf("localhost%s", port), opts)
	if err != nil {
		log.Fatalf("Failed to register gRPC-Gateway: %v", err)
	}

	// Start serving gRPC-Gateway requests
	log.Println("gRPC-Gateway server listening on :8082")
	err = http.ListenAndServe(":8082", mux)
	if err != nil {
		log.Fatalf("Failed to serve gRPC-Gateway: %v", err)
	}

}
