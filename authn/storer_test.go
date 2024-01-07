package authn

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/volatiletech/authboss/v3"
)

var ctx = context.Background()

func TestCreateStorer(t *testing.T) {
	db, _, _ := sqlmock.New()

	storer := CreateStorer(db)

	if storer.db != db {
		t.FailNow()
	}
}

func TestNewUser(t *testing.T) {
	db, _, _ := sqlmock.New()

	storer := CreateStorer(db)

	if user := ToUser(storer.New(ctx)); user.UUID == "" {
		t.FailNow()
	}
}

func TestCreateUserSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `INSERT INTO users(uuid, email, password)
		VALUES($1, $2, $3)
		RETURNING uuid, email, password`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.UUID, user.Email, user.Password).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.Create(ctx, user); err != nil {
		t.FailNow()
	}
}

func TestCreateUserErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `INSERT INTO users(uuid, email, password)
		VALUES($1, $2, $3)
		RETURNING uuid, email, password`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.UUID, user.Email, user.Password).
		WillReturnError(errors.New(""))

	if err := storer.Create(ctx, user); err == nil {
		t.FailNow()
	}
}

func TestLoadUserSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `SELECT uuid, email, password FROM users WHERE email=$1`

	const loadedEmail = "test123@test.com"
	const loadedPassword = "12345"

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.Email).
		WillReturnRows(
			sqlmock.NewRows([]string{"uuid", "email", "password"}).
				AddRow(user.UUID, loadedEmail, loadedPassword))

	isUserLoaded := func(result authboss.User) bool {
		return ToUser(result).UUID == user.UUID &&
			ToUser(result).Email == loadedEmail &&
			ToUser(result).Password == loadedPassword
	}

	if result, err := storer.Load(ctx, user.GetPID()); !isUserLoaded(result) || err != nil {
		t.FailNow()
	}
}

func TestLoadUserErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `SELECT uuid, email, password FROM users WHERE email=$1`

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.Email).
		WillReturnError(sql.ErrNoRows)

	if _, err := storer.Load(ctx, user.GetPID()); err == nil || err != authboss.ErrUserNotFound {
		t.FailNow()
	}
}

func TestSaveUserSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `UPDATE users
		SET
			password=$1
		WHERE uuid=$2
		RETURNING uuid, email, password`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.Password, user.UUID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.Save(ctx, user); err != nil {
		t.FailNow()
	}
}

func TestSaveUserErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `UPDATE users
		SET
			password=$1
		WHERE uuid=$2
		RETURNING uuid, email, password`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.Password, user.UUID).
		WillReturnError(errors.New(""))

	if err := storer.Save(ctx, user); err == nil {
		t.FailNow()
	}
}
