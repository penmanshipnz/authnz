package authboss

import (
	"testing"
)

func TestGetUUID(t *testing.T) {
	const uuid = "1234"

	user := User{
		UUID: uuid,
	}

	if user.GetUUID() != uuid {
		t.FailNow()
	}
}

func TestGetPutPid(t *testing.T) {
	const pid = "test@test.com"

	user := User{}

	user.PutPID(pid)

	if user.GetPID() != pid {
		t.FailNow()
	}
}

func TestGetPutEmail(t *testing.T) {
	const email = "test@test.com"

	user := User{}
	user.PutEmail(email)

	if user.GetEmail() != email {
		t.FailNow()
	}
}

func TestGetPutPassword(t *testing.T) {
	const password = "1234"

	user := User{}
	user.PutPassword(password)

	if user.GetPassword() != password {
		t.FailNow()
	}
}
