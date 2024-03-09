package bingauth_test

import (
	"fmt"
	"testing"

	bingauth "github.com/Harry-zklcdc/ms-auth"
)

func TestAuthPasswd(t *testing.T) {
	t.Log("Test Auth Passwd")

	auth := bingauth.NewAuth("a@b.c", "123456", bingauth.TYPE_PASSWD)
	cookie, err := auth.Auth()
	if err != nil {
		t.Error(err)
	}
	t.Log(cookie)
}

func TestAuthEmail(t *testing.T) {
	t.Log("Test Auth Email")

	auth := bingauth.NewAuth("a@b.c", "", bingauth.TYPE_EMAIL)
	cookie, err := auth.Auth()
	if err != nil {
		if err.Error() != "email login need code to continue" || auth.GetLoginType() != bingauth.TYPE_EMAIL {
			t.Error(err)
			return
		}

		var code string
		fmt.Printf("input code: ")
		fmt.Scan(&code)
		cookie, err = auth.AuthEmail(code)
		if err != nil {
			t.Error(err)
			return
		}
	}
	t.Log(cookie)
}

func TestAuthDevice(t *testing.T) {
	t.Log("Test Auth Device")

	auth := bingauth.NewAuth("a@b.c", "", bingauth.TYPE_DEVICE)
	cookie, err := auth.Auth()
	if err != nil {
		if err.Error() != "device login need handler to continue" || auth.GetLoginType() != bingauth.TYPE_DEVICE {
			t.Error(err)
			return
		}
		t.Log("Verify Code: ", cookie)

		cookie, err = auth.AuthDevice()
		if err != nil {
			t.Error(err)
			return
		}
	}
	t.Log(cookie)
}
