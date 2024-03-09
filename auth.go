package bingauth

import (
	"fmt"
	"strings"

	"github.com/Harry-zklcdc/bing-lib/lib/request"
	"golang.org/x/net/html"
)

const (
	TYPE_PASSWD = "passwd"
	TYPE_EMAIL  = "email"
	TYPE_DEVICE = "device"
)

type AuthStruct struct {
	account   string
	password  string
	loginType string

	reqClient *request.Client

	id        string
	lcid      string
	uaid      string
	flowToken string
	ppft      string
	cobrandid string

	urlGetCredentialType string
	credentialType       getCredentialTypeResp

	urlPostMsa string // Passwd Login Part 1
	urlPost    string // Passwd Login Part 1

	urlSessionState string // Device Login Part 1

	// Get Cookie
	actionUrl    string
	passportData struct {
		napExp  string
		pprid   string
		nap     string
		anon    string
		anonExp string
		t       string
	}
}

func NewAuth(account, password, loginType string) *AuthStruct {
	return &AuthStruct{
		account:   account,
		password:  password,
		loginType: loginType,
		reqClient: request.NewRequest().SetUserAgent(USER_AGENT),
	}
}

func (a *AuthStruct) Auth() (cookies string, err error) {
	if err = a.getSession(); err != nil {
		return "", fmt.Errorf("get session failed: %v", err)
	}
	if err = a.getCredentialType(); err != nil {
		return "", fmt.Errorf("get credential type failed: %v", err)
	}
	switch a.loginType {
	case TYPE_PASSWD:
		if err = a.passwdLoginPost1(); err != nil {
			return "", fmt.Errorf("passwd login post1 failed: %v", err)
		}
	case TYPE_EMAIL:
		if err = a.emailLoginPost1(); err != nil {
			return "", fmt.Errorf("email login post1 failed: %v", err)
		}
		return "", fmt.Errorf("email login need code to continue")
	case TYPE_DEVICE:
		return a.credentialType.Credentials.RemoteNgcParams.Entropy, fmt.Errorf("device login need handler to continue")
	}
	if err = a.keepLoginPost(); err != nil {
		return "", fmt.Errorf("keep login post failed: %v", err)
	}
	cookies, err = a.passport()
	if err != nil {
		return "", fmt.Errorf("get passport failed: %v", err)
	}
	return
}

func (a *AuthStruct) AuthEmail(code string) (cookies string, err error) {
	if err = a.emailLoginPost2(code); err != nil {
		return "", fmt.Errorf("email login post2 failed: %v", err)
	}
	if err = a.keepLoginPost(); err != nil {
		return "", fmt.Errorf("keep login post failed: %v", err)
	}
	cookies, err = a.passport()
	if err != nil {
		return "", fmt.Errorf("get passport failed: %v", err)
	}
	return
}

func (a *AuthStruct) AuthDevice() (cookies string, err error) {
	if err = a.deviceLoginPost1(); err != nil {
		return "", fmt.Errorf("device login post1 failed: %v", err)
	}
	if err = a.deviceLoginPost2(); err != nil {
		return "", fmt.Errorf("device login post2 failed: %v", err)
	}
	if err = a.keepLoginPost(); err != nil {
		return "", fmt.Errorf("keep login post failed: %v", err)
	}
	cookies, err = a.passport()
	if err != nil {
		return "", fmt.Errorf("get passport failed: %v", err)
	}
	return
}

func (a *AuthStruct) GetLoginType() string {
	return a.loginType
}

func getValue(s string) string {
	return strings.Split(s, "'")[1]
}

func (a *AuthStruct) findHtmlValue(n *html.Node) (node *html.Node) {
	if n.Type == html.ElementNode && n.Data == "form" {
		for _, v := range n.Attr {
			if v.Key == "action" {
				a.actionUrl = v.Val
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "NAPExp" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.napExp = v.Val
					}
				}
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "pprid" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.pprid = v.Val
					}
				}
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "NAP" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.nap = v.Val
					}
				}
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "ANON" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.anon = v.Val
					}
				}
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "ANONExp" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.anonExp = v.Val
					}
				}
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "t" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.passportData.t = v.Val
					}
				}
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		a.findHtmlValue(c)
	}
	return
}
