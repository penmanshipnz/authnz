package authboss

type User struct {
	UUID     string
	Email    string
	Password string
}

func (u *User) PutPID(pid string) {
	u.Email = pid
}

func (u *User) PutEmail(email string) {
	u.Email = email
}

func (u *User) PutPassword(password string) {
	u.Password = password
}

func (u User) GetPID() string {
	return u.Email
}

func (u User) GetUUID() string {
	return u.UUID
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetPassword() string {
	return u.Password
}
