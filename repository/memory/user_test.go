package memory

import (
	"testing"

	"github.com/m-t-a97/go-better-auth/domain/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserRepository(t *testing.T) {
	repo := NewUserRepository()
	assert.NotNil(t, repo)
}

func TestUserRepository_Create_Valid(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	assert.NoError(t, err)
	assert.NotEmpty(t, u.ID)
	assert.False(t, u.CreatedAt.IsZero())
	assert.False(t, u.UpdatedAt.IsZero())
}

func TestUserRepository_Create_Nil(t *testing.T) {
	repo := NewUserRepository()

	err := repo.Create(nil)
	assert.Error(t, err)
}

func TestUserRepository_Create_DuplicateEmail(t *testing.T) {
	repo := NewUserRepository()

	u1 := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u1)
	assert.NoError(t, err)

	u2 := &user.User{
		Name:  "Jane Doe",
		Email: "john@example.com", // Same email
	}

	err = repo.Create(u2)
	assert.Error(t, err)
}

func TestUserRepository_FindByID_Exists(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	found, err := repo.FindByID(u.ID)
	assert.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Equal(t, u.Name, found.Name)
	assert.Equal(t, u.Email, found.Email)
}

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	repo := NewUserRepository()

	found, err := repo.FindByID("non-existent-id")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_FindByEmail_Exists(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	found, err := repo.FindByEmail(u.Email)
	assert.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Equal(t, u.Name, found.Name)
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	repo := NewUserRepository()

	found, err := repo.FindByEmail("non-existent@example.com")
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_Update_Valid(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	createdAt := u.CreatedAt
	u.Name = "Jane Doe"
	err = repo.Update(u)
	assert.NoError(t, err)

	found, err := repo.FindByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, "Jane Doe", found.Name)
	assert.Equal(t, createdAt, found.CreatedAt)
	assert.True(t, found.UpdatedAt.After(createdAt))
}

func TestUserRepository_Update_NotFound(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		ID:    "non-existent-id",
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Update(u)
	assert.Error(t, err)
}

func TestUserRepository_Update_Nil(t *testing.T) {
	repo := NewUserRepository()

	err := repo.Update(nil)
	assert.Error(t, err)
}

func TestUserRepository_Delete_Valid(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	err = repo.Delete(u.ID)
	assert.NoError(t, err)

	found, err := repo.FindByID(u.ID)
	assert.Error(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	repo := NewUserRepository()

	err := repo.Delete("non-existent-id")
	assert.Error(t, err)
}

func TestUserRepository_List_Empty(t *testing.T) {
	repo := NewUserRepository()

	users, err := repo.List(10, 0)
	assert.NoError(t, err)
	assert.Empty(t, users)
}

func TestUserRepository_List_Multiple(t *testing.T) {
	repo := NewUserRepository()

	for i := 0; i < 5; i++ {
		u := &user.User{
			Name:  "User " + string(rune(i)),
			Email: "user" + string(rune('0'+i)) + "@example.com",
		}
		err := repo.Create(u)
		require.NoError(t, err)
	}

	users, err := repo.List(10, 0)
	assert.NoError(t, err)
	assert.Len(t, users, 5)
}

func TestUserRepository_List_Pagination(t *testing.T) {
	repo := NewUserRepository()

	for i := 0; i < 5; i++ {
		u := &user.User{
			Name:  "User " + string(rune(i)),
			Email: "user" + string(rune('0'+i)) + "@example.com",
		}
		err := repo.Create(u)
		require.NoError(t, err)
	}

	users, err := repo.List(2, 1)
	assert.NoError(t, err)
	assert.Len(t, users, 2)

	users, err = repo.List(10, 5)
	assert.NoError(t, err)
	assert.Empty(t, users)
}

func TestUserRepository_Count_Empty(t *testing.T) {
	repo := NewUserRepository()

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestUserRepository_Count_Multiple(t *testing.T) {
	repo := NewUserRepository()

	for i := 0; i < 5; i++ {
		u := &user.User{
			Name:  "User " + string(rune(i)),
			Email: "user" + string(rune('0'+i)) + "@example.com",
		}
		err := repo.Create(u)
		require.NoError(t, err)
	}

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestUserRepository_ExistsByEmail_Exists(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	exists, err := repo.ExistsByEmail(u.Email)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestUserRepository_ExistsByEmail_NotFound(t *testing.T) {
	repo := NewUserRepository()

	exists, err := repo.ExistsByEmail("non-existent@example.com")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestUserRepository_ExistsByID_Exists(t *testing.T) {
	repo := NewUserRepository()

	u := &user.User{
		Name:  "John Doe",
		Email: "john@example.com",
	}

	err := repo.Create(u)
	require.NoError(t, err)

	exists, err := repo.ExistsByID(u.ID)
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestUserRepository_ExistsByID_NotFound(t *testing.T) {
	repo := NewUserRepository()

	exists, err := repo.ExistsByID("non-existent-id")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestUserRepository_Concurrency(t *testing.T) {
	repo := NewUserRepository()

	// Create users concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(index int) {
			u := &user.User{
				Name:  "User " + string(rune(index)),
				Email: "user" + string(rune('0'+(index%10))) + "-" + string(rune('0'+(index/10))) + "@example.com",
			}
			_ = repo.Create(u)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	count, err := repo.Count()
	assert.NoError(t, err)
	assert.Equal(t, 10, count)
}
