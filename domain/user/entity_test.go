package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateEmail_Valid(t *testing.T) {
	tests := []string{
		"user@example.com",
		"john.doe@company.co.uk",
		"first+last@subdomain.example.com",
		"test.email+alex@leetcode.com",
	}

	for _, email := range tests {
		err := ValidateEmail(email)
		assert.NoError(t, err, "email %s should be valid", email)
	}
}

func TestValidateEmail_Invalid(t *testing.T) {
	tests := []string{
		"",
		"invalid",
		"invalid@",
		"@invalid.com",
		"invalid @example.com",
	}

	for _, email := range tests {
		err := ValidateEmail(email)
		assert.Error(t, err, "email %s should be invalid", email)
	}
}

func TestValidateEmail_TooLong(t *testing.T) {
	email := "a" + string(make([]byte, 300))
	err := ValidateEmail(email)
	assert.Error(t, err)
}

func TestValidateCreateUserRequest_Valid(t *testing.T) {
	req := &CreateUserRequest{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := ValidateCreateUserRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateUserRequest_ValidWithImage(t *testing.T) {
	imageURL := "https://example.com/image.jpg"
	req := &CreateUserRequest{
		Name:  "John Doe",
		Email: "john@example.com",
		Image: &imageURL,
	}

	err := ValidateCreateUserRequest(req)
	assert.NoError(t, err)
}

func TestValidateCreateUserRequest_Nil(t *testing.T) {
	err := ValidateCreateUserRequest(nil)
	assert.Error(t, err)
}

func TestValidateCreateUserRequest_EmptyName(t *testing.T) {
	req := &CreateUserRequest{
		Name:  "",
		Email: "john@example.com",
	}

	err := ValidateCreateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateUserRequest_NameTooLong(t *testing.T) {
	req := &CreateUserRequest{
		Name:  string(make([]byte, 300)),
		Email: "john@example.com",
	}

	err := ValidateCreateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateUserRequest_InvalidEmail(t *testing.T) {
	req := &CreateUserRequest{
		Name:  "John Doe",
		Email: "invalid-email",
	}

	err := ValidateCreateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateCreateUserRequest_ImageTooLong(t *testing.T) {
	imageURL := string(make([]byte, 3000))
	req := &CreateUserRequest{
		Name:  "John Doe",
		Email: "john@example.com",
		Image: &imageURL,
	}

	err := ValidateCreateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateUpdateUserRequest_Valid(t *testing.T) {
	name := "Updated Name"
	req := &UpdateUserRequest{
		Name: &name,
	}

	err := ValidateUpdateUserRequest(req)
	assert.NoError(t, err)
}

func TestValidateUpdateUserRequest_ValidWithImage(t *testing.T) {
	name := "Updated Name"
	imageURL := "https://example.com/new-image.jpg"
	req := &UpdateUserRequest{
		Name:  &name,
		Image: &imageURL,
	}

	err := ValidateUpdateUserRequest(req)
	assert.NoError(t, err)
}

func TestValidateUpdateUserRequest_Nil(t *testing.T) {
	err := ValidateUpdateUserRequest(nil)
	assert.Error(t, err)
}

func TestValidateUpdateUserRequest_EmptyName(t *testing.T) {
	emptyName := ""
	req := &UpdateUserRequest{
		Name: &emptyName,
	}

	err := ValidateUpdateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateUpdateUserRequest_NameTooLong(t *testing.T) {
	longName := string(make([]byte, 300))
	req := &UpdateUserRequest{
		Name: &longName,
	}

	err := ValidateUpdateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateUpdateUserRequest_ImageTooLong(t *testing.T) {
	longImage := string(make([]byte, 3000))
	req := &UpdateUserRequest{
		Image: &longImage,
	}

	err := ValidateUpdateUserRequest(req)
	assert.Error(t, err)
}

func TestValidateUpdateUserRequest_EmptyImage(t *testing.T) {
	emptyImage := ""
	req := &UpdateUserRequest{
		Image: &emptyImage,
	}

	err := ValidateUpdateUserRequest(req)
	assert.NoError(t, err)
}
