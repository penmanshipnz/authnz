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

	const query = `INSERT INTO users(
		uuid, email, password,
		confirmed, confirm_selector, confirm_verifier)
	VALUES($1, $2, $3, $4, $5, $6);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.UUID, user.Email, user.Password, user.Confirmed, user.ConfirmSelector, user.ConfirmVerifier).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.Create(ctx, user); err != nil {
		t.FailNow()
	}
}

func TestCreateUserErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `INSERT INTO users(
		uuid, email, password,
		confirmed, confirm_selector, confirm_verifier)
	VALUES($1, $2, $3, $4, $5, $6);`

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

	const query = `SELECT
			uuid, email, password,
			confirmed, confirm_selector, confirm_verifier
		FROM users
		WHERE email=$1;`

	const loadedEmail = "test123@test.com"
	const loadedPassword = "12345"

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.Email).
		WillReturnRows(
			sqlmock.NewRows([]string{"uuid", "email", "password",
				"confirmed", "confirm_selector", "confirm_verifier"}).
				AddRow(user.UUID, loadedEmail, loadedPassword,
					user.Confirmed, user.ConfirmSelector, user.ConfirmVerifier))

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

	const query = `SELECT
			uuid, email, password,
			confirmed, confirm_selector, confirm_verifier
		FROM users
		WHERE email=$1;`

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
			password=$1,
			confirmed=$2,
			confirm_selector=$3,
			confirm_verifier=$4
		WHERE uuid=$5;`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.Password, user.Confirmed, user.ConfirmSelector, user.ConfirmVerifier, user.UUID).
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
			password=$1,
			confirmed=$2,
			confirm_selector=$3,
			confirm_verifier=$4
		WHERE uuid=$5;`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(user.Password, user.Confirmed, user.ConfirmSelector, user.ConfirmVerifier, user.UUID).
		WillReturnError(errors.New(""))

	if err := storer.Save(ctx, user); err == nil {
		t.FailNow()
	}
}

func TestAddRememberTokenSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const token = "1234"
	const email = "1234"

	const query = `INSERT INTO remember_tokens(authenticatee, tokens)
		VALUES(
			(SELECT uuid FROM users WHERE email=$1),
			ARRAY[$2])
		ON CONFLICT (authenticatee)
		DO
			UPDATE SET tokens=array_append(remember_tokens.tokens, $2);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(token, email).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.AddRememberToken(ctx, email, token); err != nil {
		t.FailNow()
	}
}

func TestAddRememberTokenErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const token = "1234"
	const email = "1234"

	const query = `INSERT INTO remember_tokens(authenticatee, tokens)
		VALUES(
			(SELECT uuid FROM users WHERE email=$1),
			ARRAY[$2])
		ON CONFLICT (authenticatee)
		DO
			UPDATE SET tokens=array_append(remember_tokens.tokens, $2);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(token, email).
		WillReturnError(errors.New(""))

	if err := storer.AddRememberToken(ctx, email, token); err == nil {
		t.FailNow()
	}
}

func TestDelRememberTokensSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const email = "1234"

	const query = `INSERT INTO remember_tokens(authenticatee, tokens)
		VALUES(
			(SELECT uuid FROM users WHERE email=$1),
			ARRAY[])
		ON CONFLICT (authenticatee)
		DO
			UPDATE SET tokens=NULL;`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(email).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.DelRememberTokens(ctx, email); err != nil {
		t.FailNow()
	}
}

func TestDelRememberTokensErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const email = "1234"

	const query = `INSERT INTO remember_tokens(authenticatee, tokens)
		VALUES(
			(SELECT uuid FROM users WHERE email=$1),
			ARRAY[])
		ON CONFLICT (authenticatee)
		DO
			UPDATE SET tokens=NULL;`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(email).
		WillReturnError(errors.New(""))

	if err := storer.DelRememberTokens(ctx, email); err == nil {
		t.FailNow()
	}
}

func TestUseRememberTokenSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const token = "1234"
	const email = "1234"

	const query = `UPDATE remember_tokens
		SET
			tokens=array_remove(tokens, $1)
		WHERE
			authenticatee=(SELECT uuid FROM users WHERE email=$2)
		AND
			$1=ANY(tokens);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(token, email).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := storer.UseRememberToken(ctx, email, token); err != nil {
		t.FailNow()
	}
}

func TestUseRememberTokenErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const token = "1234"
	const email = "1234"

	const query = `UPDATE remember_tokens
		SET
			tokens=array_remove(tokens, $1)
		WHERE
			authenticatee=(SELECT uuid FROM users WHERE email=$2)
		AND
			$1=ANY(tokens);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(token, email).
		WillReturnError(errors.New(""))

	if err := storer.UseRememberToken(ctx, email, token); err == nil {
		t.FailNow()
	}
}

func TestUseRememberErrTokenNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)

	const token = "1234"
	const email = "1234"

	const query = `UPDATE remember_tokens
		SET
			tokens=array_remove(tokens, $1)
		WHERE
			authenticatee=(SELECT uuid FROM users WHERE email=$2)
		AND
			$1=ANY(tokens);`

	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(token, email).
		WillReturnResult(sqlmock.NewResult(1, 0))

	if err := storer.UseRememberToken(ctx, email, token); err != authboss.ErrTokenNotFound {
		t.FailNow()
	}
}

func TestLoadByConfirmSelectorSuccess(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `SELECT uuid, email, password, confirmed, confirm_selector, confirm_verifier
	FROM users
	WHERE confirm_selector=$1`

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.ConfirmSelector).
		WillReturnRows(
			sqlmock.NewRows([]string{
				"uuid", "email", "password",
				"confirmed", "confirm_selector", "confirm_verifier"}).
				AddRow(user.UUID, user.Email, user.Password,
					user.Confirmed, user.ConfirmSelector, user.ConfirmVerifier))

	if cu, err := storer.LoadByConfirmSelector(ctx, user.ConfirmSelector); err != nil || ToUser(cu).UUID != user.UUID {
		t.FailNow()
	}
}

func TestLoadByConfirmSelectorErr(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `SELECT uuid, email, password, confirmed, confirm_selector, confirm_verifier
	FROM users
	WHERE confirm_selector=$1`

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.ConfirmSelector).
		WillReturnError(errors.New(""))

	if _, err := storer.LoadByConfirmSelector(ctx, user.ConfirmSelector); err == nil {
		t.FailNow()
	}
}

func TestLoadByConfirmSelectorErrUserNotFound(t *testing.T) {
	db, mock, _ := sqlmock.New()

	storer := CreateStorer(db)
	user := ToUser(storer.New(ctx))

	const query = `SELECT uuid, email, password, confirmed, confirm_selector, confirm_verifier
	FROM users
	WHERE confirm_selector=$1`

	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(user.ConfirmSelector).
		WillReturnError(sql.ErrNoRows)

	if _, err := storer.LoadByConfirmSelector(ctx, user.ConfirmSelector); err == nil || err != authboss.ErrUserNotFound {
		t.FailNow()
	}
}
