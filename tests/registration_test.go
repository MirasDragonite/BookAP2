package main

import (
	"context"
	"testing"

	pb "UserService/userserver/test"

	"github.com/stretchr/testify/assert"
)

type mockServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *mockServer) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {

	return &pb.RegisterUserResponse{
		User: &pb.User{
			Id:        1,
			Name:      req.User.Name,
			Email:     req.User.Email,
			Activated: false,
			Roles:     req.User.Roles,
		},
	}, nil
}

func TestRegisterUser(t *testing.T) {

	mockServer := &mockServer{}

	request := &pb.RegisterUserRequest{
		User: &pb.User{
			Name:     "John Doe",
			Email:    "john@example.com",
			Password: "password",
			Roles:    "user",
		},
	}

	// Call the RegisterUser method on the mock server
	response, err := mockServer.RegisterUser(context.Background(), request)

	// Check the expected results
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotNil(t, response.User)
	assert.NotEmpty(t, response.User.Id)
	assert.Equal(t, request.User.Name, response.User.Name)
	assert.Equal(t, request.User.Email, response.User.Email)
	assert.False(t, response.User.Activated)
	// Add additional assertions as needed
}

// Add more test functions for other functions if required
