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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/Matfej28/ProgressTracking/pkg/dotEnv"
	"github.com/Matfej28/ProgressTracking/pkg/hashing"
	"github.com/Matfej28/ProgressTracking/pkg/jwtToken"
	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
)

const port = ":8080"

type ProgressTrackingServer struct {
	pb.UnimplementedProgressTrackingServer
}

type repRange struct {
	Min uint32
	Max uint32
}

type set struct {
	Weight float64
	Reps   uint32
}

type Record struct {
	Username           string
	MuscleGroup        string
	Exercise           string
	Reps               repRange
	LastTraining       []set
	BeforeLastTraining []set
	Pr                 set
}

func (s *ProgressTrackingServer) Registration(ctx context.Context, request *pb.RegistrationRequest) (*pb.RegistrationResponse, error) {
	dotEnv.LoadDotEnv()
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
	dotEnv.LoadDotEnv()
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
	dotEnv.LoadDotEnv()
	err := jwtToken.CheckToken("AUTH_KEY", ctx)
	if err != nil {
		return nil, err
	}

	username, err := jwtToken.UsernameFromToken("AUTH_KEY", ctx)
	if err != nil {
		return nil, err
	}

	clientOpts := options.Client().ApplyURI("mongodb://localhost:27017/?connect=direct")
	client, err := mongo.Connect(context.TODO(), clientOpts)
	if err != nil {
		log.Fatal(err)
	}

	defer func() error {
		if err := client.Disconnect(ctx); err != nil {
			return err
		}
		return nil
	}()

	coll := client.Database("ProgressTracking").Collection("ProgressTracking")
	filter := bson.D{{"username", username}}

	var record Record
	err = coll.FindOne(context.TODO(), filter).Decode(&record)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("the field that you want to find does not exist")
		}
		return nil, err
	}
	log.Println(record)
	return &pb.GetRecordsResponse{}, nil
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
