package authn

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/volatiletech/authboss/v3"
)

type Storer struct {
	db *sql.DB
}

func CreateStorer(db *sql.DB) *Storer {
	return &Storer{
		db: db,
	}
}

/*
CreateServerStorer interface

New creates a blank user, it is not yet persisted in the database
but is just for storing data
*/
func (store Storer) New(_ context.Context) authboss.User {
	uuid, _ := uuid.NewV6()

	return &User{
		UUID: uuid.String(),
	}
}

/*
CreateServerStorer interface

Create the user in storage, it should not overwrite a user
and should return ErrUserFound if it currently exists.
*/
func (storer Storer) Create(ctx context.Context, abu authboss.User) error {
	user := ToUser(abu)

	const query = `INSERT INTO users(uuid, email, password)
		VALUES($1, $2, $3)
		RETURNING uuid, email, password`
	_, err := storer.db.ExecContext(ctx, query, user.UUID, user.Email, user.Password)

	return err
}

/*
ServerStorer interface

Load will look up the user based on the passed the PrimaryID. Under
normal circumstances this comes from GetPID() of the user.

OAuth2 logins are special-cased to return an OAuth2 pid (combination of
provider:oauth2uid), and therefore key be special cased in a Load()
implementation to handle that form, use ParseOAuth2PID to see
if key is an OAuth2PID or not.
*/
func (storer Storer) Load(ctx context.Context, email string) (authboss.User, error) {
	var user User

	const query = `SELECT uuid, email, password FROM users WHERE email=$1`
	row := storer.db.QueryRowContext(ctx, query, email)

	if err := row.Scan(&user.UUID, &user.Email, &user.Password); err != nil {
		if err == sql.ErrNoRows {
			return &user, authboss.ErrUserNotFound
		}

		return &user, err
	}

	return &user, nil
}

/*
ServerStorer interface

Save persists the user in the database, this should never
create a user and instead return ErrUserNotFound if the user
does not exist.
*/
func (storer Storer) Save(ctx context.Context, abu authboss.User) error {
	user := ToUser(abu)

	const query = `UPDATE users
		SET
			password=$1
		WHERE uuid=$2
		RETURNING uuid, email, password`
	_, err := storer.db.ExecContext(ctx, query, user.Password, user.UUID)

	return err
}

func ToUser(user authboss.User) *User {
	return user.(*User)
}
