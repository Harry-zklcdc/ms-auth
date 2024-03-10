package bingauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
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
		d, _ := json.Marshal(auth)

		var code string
		fmt.Printf("input code: ")
		fmt.Scan(&code)
		auth = bingauth.NewAuth("a@b.c", "", bingauth.TYPE_EMAIL)
		auth.SetContext(d)
		auth.SetCookie(cookie)
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
		if !strings.HasPrefix(err.Error(), "device login need handler to continue") || auth.GetLoginType() != bingauth.TYPE_DEVICE {
			t.Error(err)
			return
		}
		d, _ := json.Marshal(auth)
		code := strings.Split(err.Error(), "code: ")[1]
		t.Log("Verify Code: ", code)
		auth := bingauth.NewAuth("a@b.c", "", bingauth.TYPE_DEVICE)
		auth.SetContext(d)
		auth.SetCookie(cookie)
		cookie, err = auth.AuthDevice()
		if err != nil {
			t.Error(err)
			return
		}
	}
	t.Log(cookie)
}
