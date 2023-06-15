package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"

	pb "UserService/userserver/test"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/stdlib"
)

const (
	port           = ":50052"
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
	db *pgx.Conn
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

	err = s.db.QueryRow(ctx, stmt,
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

	row := s.db.QueryRow(ctx, stmt, activation_token)

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

func main() {
	db, err := sql.Open("pgx", "postgres://postgres:76205527@localhost:5432/bookstore")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	pgxConn, err := stdlib.AcquireConn(db)
	if err != nil {
		log.Fatalf("Failed to acquire pgx connection: %v", err)
	}
	defer stdlib.ReleaseConn(db, pgxConn)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &server{db: pgxConn})
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
	log.Println("gRPC-Gateway server listening on :8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Failed to serve gRPC-Gateway: %v", err)
	}

}
