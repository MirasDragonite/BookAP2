package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"google.golang.org/grpc"

	pb "Booking/bookserver/test"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgtype"
	_ "github.com/lib/pq"
)

const (
	port = ":50052"
)

type server struct {
	pb.UnimplementedBookingServiceServer
	db *sql.DB
}

func (s *server) CreateBook(ctx context.Context, req *pb.CreateBookRequest) (*pb.Book, error) {
	book := req.GetBook()

	sqlStatement := `
		INSERT INTO books (title, author, year, language, genres, price, quantity)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`

	genresArray := &pgtype.TextArray{}
	if err := genresArray.Set(book.Genres); err != nil {
		log.Printf("Failed to convert genres to array-compatible format: %v", err)
		return nil, err
	}

	var id int64
	err := s.db.QueryRowContext(
		ctx,
		sqlStatement,
		book.Title,
		book.Author,
		book.Year,
		book.Language,
		genresArray,
		book.Price,
		book.Quantity,
	).Scan(&id)
	if err != nil {
		log.Printf("Failed to create book: %v", err)
		return nil, err
	}

	book.Id = id

	return book, nil
}

func (s *server) ReadBook(ctx context.Context, req *pb.ReadBookRequest) (*pb.Book, error) {
	bookID := req.GetId()

	sqlStatement := `
		SELECT id, title, author, year, language, genres, price, quantity
		FROM books
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, sqlStatement, bookID)

	book := &pb.Book{}

	err := row.Scan(
		&book.Id,
		&book.Title,
		&book.Author,
		&book.Year,
		&book.Language,
		&book.Genres,
		&book.Price,
		&book.Quantity,
	)
	if err != nil {
		log.Printf("Failed to read book: %v", err)
		return nil, err
	}

	return book, nil
}

func (s *server) UpdateBook(ctx context.Context, req *pb.UpdateBookRequest) (*pb.Book, error) {
	bookID := req.GetId()
	updatedBook := req.GetBook()

	sqlStatement := `
		UPDATE books
		SET title = $1, author = $2, year = $3, language = $4, genres = $5, price = $6, quantity = $7
		WHERE id = $8
		RETURNING id
	`

	genresArray := &pgtype.TextArray{}
	if err := genresArray.Set(updatedBook.Genres); err != nil {
		log.Printf("Failed to convert genres to array-compatible format: %v", err)
		return nil, err
	}

	var id int64
	err := s.db.QueryRowContext(
		ctx,
		sqlStatement,
		updatedBook.Title,
		updatedBook.Author,
		updatedBook.Year,
		updatedBook.Language,
		genresArray,
		updatedBook.Price,
		updatedBook.Quantity,
		bookID,
	).Scan(&id)
	if err != nil {
		log.Printf("Failed to update book: %v", err)
		return nil, err
	}

	updatedBook.Id = id
	return updatedBook, nil
}

func (s *server) DeleteBook(ctx context.Context, req *pb.DeleteBookRequest) (*pb.DeleteBookResponse, error) {
	bookID := req.GetId()

	sqlStatement := `
		DELETE FROM books
		WHERE id = $1
	`

	_, err := s.db.ExecContext(ctx, sqlStatement, bookID)
	if err != nil {
		log.Printf("Failed to delete book: %v", err)
		return nil, err
	}

	response := &pb.DeleteBookResponse{
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

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterBookingServiceServer(s, &server{db: db})

	log.Printf("gRPC server listening on %s", port)
	go func() {
		err = s.Serve(lis)
		if err != nil {
			log.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err = pb.RegisterBookingServiceHandlerFromEndpoint(context.Background(), mux, fmt.Sprintf("localhost%s", port), opts)
	if err != nil {
		log.Fatalf("Failed to register gRPC-Gateway: %v", err)
	}

	log.Println("gRPC-Gateway server listening on :8081")
	err = http.ListenAndServe(":8081", mux)
	if err != nil {
		log.Fatalf("Failed to serve gRPC-Gateway: %v", err)
	}
}
