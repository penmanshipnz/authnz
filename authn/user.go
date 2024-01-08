package authn

type User struct {
	UUID            string
	Email           string
	Password        string
	ConfirmSelector string
	ConfirmVerifier string
	Confirmed       bool
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

func (u *User) PutConfirmed(confirmed bool) {
	u.Confirmed = confirmed
}

func (u *User) PutConfirmSelector(confirmSelector string) {
	u.ConfirmSelector = confirmSelector
}

func (u *User) PutConfirmVerifier(confirmVerifier string) {
	u.ConfirmVerifier = confirmVerifier
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

func (u User) GetConfirmed() bool {
	return u.Confirmed
}

func (u User) GetConfirmSelector() string {
	return u.ConfirmSelector
}

func (u User) GetConfirmVerifier() string {
	return u.ConfirmVerifier
}
