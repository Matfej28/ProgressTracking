package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/mail"

	pb "github.com/Matfej28/ProgressTracking/proto"
	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
)

const port = ":8080"

type ProgressTrackingServer struct {
	pb.UnimplementedProgressTrackingServer
}

func (s *ProgressTrackingServer) Registration(ctx context.Context, request *pb.RegistrationRequest) (*pb.RegistrationResponse, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", "root", "marelli28", "localhost", "3306", "progresstracking"))
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

	salt := hashing.generateSalt()
	password = hashing.hashPassword(password, salt)
	log.Println(salt)
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

	return &pb.RegistrationResponse{Token: password}, nil
}
func (s *ProgressTrackingServer) LogIn(ctx context.Context, request *pb.LogInRequest) (*pb.LogInResponse, error) {
	return nil, fmt.Errorf("method Registration not implemented")
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
		log.Fatal("failed to serve: %v", err)
	}
}
