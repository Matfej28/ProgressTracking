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
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	err := dotEnv.LoadDotEnv()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_HOST"), os.Getenv("MYSQL_PORT"), os.Getenv("MYSQL_DATABASE")))
	defer db.Close()
	if err != nil {
		return nil, err
	}

	pingErr := db.Ping()
	if pingErr != nil {
		return nil, err
	}

	username := request.GetUsername()
	if len(username) < 1 {
		return nil, fmt.Errorf("too short username: enter at least one symbol")
	}

	rows, err := db.Query(fmt.Sprintf("SELECT * FROM `users` WHERE `username`='%s';", username))
	if err != nil {
		return nil, err
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
		return nil, err
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

	salt, err := hashing.GenerateSalt()
	if err != nil {
		return nil, err
	}

	hashedPassword, err := hashing.HashPassword([]byte(password), salt)
	if err != nil {
		return nil, err
	}

	_, err = db.Query(fmt.Sprintf("INSERT INTO `users` (`username`, `email`, `salt`, `hashedpassword`) VALUES ('%s', '%s', '%s', '%s');", username, email, salt, hashedPassword))
	if err != nil {
		return nil, err
	}

	token, err := jwtToken.CreateToken(os.Getenv("AUTH_KEY"), username, email)
	if err != nil {
		return nil, err
	}

	return &pb.RegistrationResponse{Token: token}, nil
}

func (s *ProgressTrackingServer) LogIn(ctx context.Context, request *pb.LogInRequest) (*pb.LogInResponse, error) {
	err := dotEnv.LoadDotEnv()
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_HOST"), os.Getenv("MYSQL_PORT"), os.Getenv("MYSQL_DATABASE")))
	defer db.Close()
	if err != nil {
		return nil, err
	}

	pingErr := db.Ping()
	if pingErr != nil {
		return nil, err
	}

	email := request.GetEmail()
	rows, err := db.Query(fmt.Sprintf("SELECT `username`, `salt`, `hashedpassword` FROM `users` WHERE `email`='%s';", email))
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, fmt.Errorf("incorrect email or password")
	}

	var username string
	var salt, hashedPassword []byte
	if err := rows.Scan(&username, &salt, &hashedPassword); err != nil {
		return nil, err
	}
	rows.Close()

	password := request.GetPassword()
	if !hashing.CheckHashedPassword(hashedPassword, []byte(password), salt) {
		return nil, fmt.Errorf("incorrect email or password")
	}

	token, err := jwtToken.CreateToken(os.Getenv("AUTH_KEY"), username, email)
	if err != nil {
		return nil, err
	}

	return &pb.LogInResponse{Token: token}, nil
}

func (s *ProgressTrackingServer) GetRecords(ctx context.Context, request *pb.GetRecordsRequest) (*pb.GetRecordsResponse, error) {
	err := dotEnv.LoadDotEnv()
	if err != nil {
		return nil, err
	}

	key := os.Getenv("AUTH_KEY")
	err = jwtToken.CheckToken(key, ctx)
	if err != nil {
		return nil, err
	}

	username, err := jwtToken.UsernameFromToken(key, ctx)
	if err != nil {
		return nil, err
	}

	clientOpts := options.Client().ApplyURI("mongodb://localhost:27017/?connect=direct")
	client, err := mongo.Connect(context.TODO(), clientOpts)
	if err != nil {
		return nil, err
	}

	defer func() error {
		if err := client.Disconnect(ctx); err != nil {
			return err
		}
		return nil
	}()

	coll := client.Database("ProgressTracking").Collection("ProgressTracking")

	muscleGroup := request.GetMuscleGroup()
	exercise := request.GetExercise()
	repRange := request.GetReps()
	filter := bson.D{{"username", username}}
	if muscleGroup != "" {
		filter = append(filter, primitive.E{"muscleGroup", muscleGroup})
	}
	if exercise != "" {
		filter = append(filter, primitive.E{"exercise", exercise})
	}
	if repRange != nil {
		filter = append(filter, primitive.E{"reps", repRange})
	}

	var records []*pb.Record
	cursor, err := coll.Find(context.TODO(), filter)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("the field that you want to find does not exist")
		}
		return nil, err
	}

	if err = cursor.All(ctx, &records); err != nil {
		return nil, err
	}

	return &pb.GetRecordsResponse{Record: records}, nil
}

func (s *ProgressTrackingServer) UpdateRecords(ctx context.Context, request *pb.UpdateRecordsRequest) (*pb.UpdateRecordsResponse, error) {
	err := dotEnv.LoadDotEnv()
	if err != nil {
		return nil, err
	}

	key := os.Getenv("AUTH_KEY")
	err = jwtToken.CheckToken(key, ctx)
	if err != nil {
		return nil, err
	}

	username, err := jwtToken.UsernameFromToken(key, ctx)
	if err != nil {
		return nil, err
	}

	clientOpts := options.Client().ApplyURI("mongodb://localhost:27017/?connect=direct")
	client, err := mongo.Connect(context.TODO(), clientOpts)
	if err != nil {
		return nil, err
	}

	defer func() error {
		if err := client.Disconnect(ctx); err != nil {
			return err
		}
		return nil
	}()

	coll := client.Database("ProgressTracking").Collection("ProgressTracking")

	muscleGroup := request.GetMuscleGroup()
	exercise := request.GetExercise()
	repRange := request.GetReps()
	sets := request.GetSets()

	filter := bson.D{{"username", username}, {"muscleGroup", muscleGroup}, {"exercise", exercise}, {"reps", repRange}}

	var record *pb.Record

	res := coll.FindOne(ctx, filter)
	if err = res.Decode(&record); err != nil {
		if err == mongo.ErrNoDocuments {
			filter = append(filter, primitive.E{"lastTraining", sets})

			_, err := coll.InsertOne(ctx, filter)
			if err != nil {
				return nil, err
			}

			record = &pb.Record{MuscleGroup: muscleGroup, Exercise: exercise, Reps: repRange, LastTraining: sets}
			return &pb.UpdateRecordsResponse{Record: record}, nil
		}
		return nil, err
	}

	filter = append(filter, primitive.E{"lastTraining", sets}, primitive.E{"beforeLastTraining", record.LastTraining})
	record.LastTraining, record.BeforeLastTraining = sets, record.LastTraining
	return &pb.UpdateRecordsResponse{Record: record}, nil
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
