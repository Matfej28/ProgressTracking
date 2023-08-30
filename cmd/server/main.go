package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/mail"
	"os"

	pb "github.com/Matfej28/ProgressTracking/proto"
	"github.com/joho/godotenv"

	"github.com/Matfej28/ProgressTracking/pkg/hashing"
	"github.com/Matfej28/ProgressTracking/pkg/jwtToken"

	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
)

const port = ":8080"

type ProgressTrackingServer struct {
	pb.UnimplementedProgressTrackingServer
}

func (s *ProgressTrackingServer) Registration(ctx context.Context, request *pb.RegistrationRequest) (*pb.RegistrationResponse, error) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_HOST"), os.Getenv("MYSQL_PORT"), os.Getenv("MYSQL_DATABASE")))
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(err)
	}

	username := request.GetUsername()
	if len(username) < 1 {
		return nil, fmt.Errorf("too short username: enter at least one symbol")
	}

	rows, err := db.Query(fmt.Sprintf("SELECT * FROM `users` WHERE `username`='%s';", username))
	if err != nil {
		log.Fatal(err)
	}
	if rows.Next() {
		return nil, fmt.Errorf("user with this username already exists")
	}
	rows.Close()

	email := request.GetEmail()
	_, err = mail.ParseAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email")
	}

	rows, err = db.Query(fmt.Sprintf("SELECT * FROM `users` WHERE `email`='%s';", email))
	if err != nil {
		log.Fatal(err)
	}
	if rows.Next() {
		return nil, fmt.Errorf("user with this email already exists")
	}
	rows.Close()

	password := request.GetPassword()
	if len(password) < 6 {
		return nil, fmt.Errorf("too short password: enter at least six symbols")
	}

	confirmPassword := request.GetConfirmPassword()
	if password != confirmPassword {
		return nil, fmt.Errorf("password is not confirmed")
	}

	salt := hashing.GenerateSalt()
	password = hashing.HashPassword(password, salt)
	_, err = db.Query(fmt.Sprintf("INSERT INTO `users` (`username`, `email`, `salt`, `hashedpassword`) VALUES ('%s', '%s', '%s', '%s');", username, email, salt, password))
	if err != nil {
		log.Fatal(err)
	}

	rows, err = db.Query(fmt.Sprintf("SELECT `hashedpassword` FROM `users` WHERE `email`='%s';", email))
	if err != nil {
		log.Fatal(err)
	}
	rows.Next()
	if err := rows.Scan(&password); err != nil {
		log.Fatal(err)
	}
	rows.Close()

	token := jwtToken.CreateToken(os.Getenv("AUTH_KEY"), username, email)

	return &pb.RegistrationResponse{Token: token}, nil
}

func (s *ProgressTrackingServer) LogIn(ctx context.Context, request *pb.LogInRequest) (*pb.LogInResponse, error) {
	err := godotenv.Load("github.com/Matfej28/ProgressTracking/.env")
	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_HOST"), os.Getenv("MYSQL_PORT"), os.Getenv("MYSQL_DATABASE")))
	defer db.Close()
	if err != nil {
		log.Fatal(err)
	}

	pingErr := db.Ping()
	if pingErr != nil {
		log.Fatal(err)
	}

	email := request.GetEmail()
	rows, err := db.Query(fmt.Sprintf("SELECT `username`, `salt`, `hashedpassword` FROM `users` WHERE `email`='%s';", email))
	if err != nil {
		log.Fatal(err)
	}
	if !rows.Next() {
		return nil, fmt.Errorf("incorrect email or password")
	}

	username := ""
	salt := ""
	hashedPassword := ""
	if err := rows.Scan(&username, &salt, &hashedPassword); err != nil {
		log.Fatal(err)
	}
	rows.Close()

	password := request.GetPassword()
	if !hashing.CheckHashedPassword(hashedPassword, password+salt) {
		return nil, fmt.Errorf("incorrect email or password")
	}

	token := jwtToken.CreateToken(os.Getenv("AUTH_KEY"), username, email)

	return &pb.LogInResponse{Token: token}, nil
}

func (s *ProgressTrackingServer) GetRecords(ctx context.Context, request *pb.GetRecordsRequest) (*pb.GetRecordsResponse, error) {
	return nil, fmt.Errorf("method Registration not implemented")
}

func (s *ProgressTrackingServer) UpdateRecords(ctx context.Context, request *pb.UpdateRecordsRequest) (*pb.UpdateRecordsResponse, error) {
	return nil, fmt.Errorf("method Registration not implemented")
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterProgressTrackingServer(s, &ProgressTrackingServer{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
