package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"

	pb "comicService/comicserver/test"
)

const (
	port = ":50051"
)

type server struct {
	pb.UnimplementedComicsServiceServer
	db *sql.DB
}

func (s *server) CreateComic(ctx context.Context, req *pb.CreateComicRequest) (*pb.Comic, error) {
	comic := req.GetComic()

	var id int64

	sqlStatement := `
		INSERT INTO comics ( title, author, year, language, price, quantity, publisher)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`

	err := s.db.QueryRowContext(
		ctx,
		sqlStatement,

		comic.GetTitle(),
		comic.GetAuthor(),
		comic.GetYear(),
		comic.GetLanguage(),
		comic.GetPrice(),
		comic.GetQuantity(),
		comic.GetPublisher(),
	).Scan(&id)
	if err != nil {
		log.Printf("Failed to create comic: %v", err)
		return nil, err
	}

	comic.Id = id
	return comic, nil
}

func (s *server) ReadComic(ctx context.Context, req *pb.ReadComicRequest) (*pb.Comic, error) {
	id := req.GetId()

	sqlStatement := `
		SELECT id, title, author, year, language, price, quantity, publisher
		FROM comics
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, sqlStatement, id)

	comic := &pb.Comic{}

	err := row.Scan(
		&comic.Id,
		&comic.Title,
		&comic.Author,
		&comic.Year,
		&comic.Language,
		&comic.Price,
		&comic.Quantity,
		&comic.Publisher,
	)
	if err != nil {
		log.Printf("Failed to read comic: %v", err)
		return nil, err
	}

	return comic, nil
}

func (s *server) UpdateComic(ctx context.Context, req *pb.UpdateComicRequest) (*pb.Comic, error) {
	id := req.GetId()
	updatedComic := req.GetComic()

	sqlStatement := `
		UPDATE comics
		SET title = $1, author = $2, year = $3, language = $4, price = $5, quantity = $6, publisher = $7
		WHERE id = $8
		RETURNING id
	`

	err := s.db.QueryRowContext(
		ctx,
		sqlStatement,
		updatedComic.GetTitle(),
		updatedComic.GetAuthor(),
		updatedComic.GetYear(),
		updatedComic.GetLanguage(),
		updatedComic.GetPrice(),
		updatedComic.GetQuantity(),
		updatedComic.GetPublisher(),
		id,
	).Scan(&id)
	if err != nil {
		log.Printf("Failed to update comic: %v", err)
		return nil, err
	}

	updatedComic.Id = id
	return updatedComic, nil
}

func (s *server) DeleteComic(ctx context.Context, req *pb.DeleteComicRequest) (*pb.DeleteComicResponse, error) {
	id := req.GetId()

	sqlStatement := `
		DELETE FROM comics
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, sqlStatement, id)
	if err != nil {
		log.Printf("Failed to delete comic: %v", err)
		return nil, err
	}

	response := &pb.DeleteComicResponse{
		Success: true,
	}
	return response, nil
}

func main() {
	host := os.Getenv("DB_HOST")
	portDB := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portDB, user, password, dbname)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	//grpc
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterComicsServiceServer(s, &server{db: db})

	log.Printf("gRPC server listening on %s", port)
	go func() {
		err = s.Serve(lis)
		if err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err = pb.RegisterComicsServiceHandlerFromEndpoint(context.Background(), mux, fmt.Sprintf("localhost%s", port), opts)
	if err != nil {
		log.Fatalf("Failed to register gRPC-Gateway: %v", err)
	}

	log.Println("gRPC-Gateway server listening on :8080")
	err = http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Failed to serve gRPC-Gateway: %v", err)
	}
}
