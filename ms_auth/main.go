package main

/*
struct Auth {
	char* cookies;
	char* ctx;
	char* errStr;
};
*/
import "C"
import (
	"encoding/json"
	"os"
	"os/signal"
	"strings"
	"syscall"

	msauth "github.com/Harry-zklcdc/ms-auth"
)

func init() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		os.Exit(1)
	}()
}

func main() {}

//export auth
func auth(a, p, at *C.char) C.struct_Auth {
	account := C.GoString(a)
	passwd := C.GoString(p)
	authType := C.GoString(at)
	msau := msauth.NewAuth(account, passwd, authType)
	cookiesRaw, err := msau.Auth()
	if err != nil {
		if !strings.HasPrefix(err.Error(), "device login need handler to continue") && err.Error() != "email login need code to continue" {
			return C.struct_Auth{C.CString(""), C.CString(""), C.CString(err.Error())}
		}
	}
	d, _ := json.Marshal(msau)
	if err == nil {
		return C.struct_Auth{C.CString(cookiesRaw), C.CString(string(d)), C.CString("")}
	}
	return C.struct_Auth{C.CString(cookiesRaw), C.CString(string(d)), C.CString(err.Error())}
}

//export authEmail
func authEmail(a, c, at, ctx, ck *C.char) C.struct_Auth {
	account := C.GoString(a)
	code := C.GoString(c)
	authType := C.GoString(at)
	context := C.GoString(ctx)
	cookies := C.GoString(ck)
	if authType != msauth.TYPE_EMAIL {
		return C.struct_Auth{C.CString(""), C.CString(""), C.CString("auth type must be email")}
	}
	msau := msauth.NewAuth(account, "", authType)
	msau.SetContext([]byte(context))
	msau.SetCookie(cookies)
	cookiesRaw, err := msau.AuthEmail(code)
	if err != nil {
		return C.struct_Auth{C.CString(""), C.CString(""), C.CString(err.Error())}
	}
	d, _ := json.Marshal(msau)
	return C.struct_Auth{C.CString(cookiesRaw), C.CString(string(d)), C.CString("")}
}

//export authDevice
func authDevice(a, at, ctx, cookie *C.char) C.struct_Auth {
	account := C.GoString(a)
	authType := C.GoString(at)
	context := C.GoString(ctx)
	cookies := C.GoString(cookie)
	if authType != msauth.TYPE_DEVICE {
		return C.struct_Auth{C.CString(""), C.CString(""), C.CString("auth type must be device")}
	}
	msau := msauth.NewAuth(account, "", authType)
	msau.SetContext([]byte(context))
	msau.SetCookie(cookies)
	cookiesRaw, err := msau.AuthDevice()
	if err != nil {
		return C.struct_Auth{C.CString(""), C.CString(""), C.CString(err.Error())}
	}
	d, _ := json.Marshal(msau)
	return C.struct_Auth{C.CString(cookiesRaw), C.CString(string(d)), C.CString("")}
}
