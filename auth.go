package bingauth

import (
	"encoding/json"
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
	Account   string
	Password  string
	LoginType string

	reqClient *request.Client

	Id        string
	Lcid      string
	Uaid      string
	FlowToken string
	Ppft      string
	Cobrandid string

	UrlGetCredentialType string
	CredentialType       getCredentialTypeResp

	UrlPostMsa string // Passwd Login Part 1
	UrlPost    string // Passwd Login Part 1

	UrlSessionState string // Device Login Part 1

	// Get Cookie
	ActionUrl    string
	PassportData struct {
		NAPExp  string
		PPRID   string
		NAP     string
		ANON    string
		ANONExp string
		T       string
	}
}

func NewAuth(account, password, loginType string) *AuthStruct {
	return &AuthStruct{
		Account:   account,
		Password:  password,
		LoginType: loginType,
		reqClient: request.NewRequest().SetUserAgent(USER_AGENT),
	}
}

func (a *AuthStruct) SetCookie(cookies string) (err error) {
	a.reqClient.SetCookies(cookies)
	return
}

func (a *AuthStruct) SetContext(ctx []byte) (err error) {
	cookies := a.reqClient.Cookies
	err = json.Unmarshal(ctx, a)
	if err != nil {
		return
	}
	a.reqClient.Cookies = cookies
	return
}

func (a *AuthStruct) Auth() (cookies string, err error) {
	if err = a.getSession(); err != nil {
		return "", fmt.Errorf("get session failed: %v", err)
	}
	if err = a.getCredentialType(); err != nil {
		return "", fmt.Errorf("get credential type failed: %v", err)
	}
	switch a.LoginType {
	case TYPE_PASSWD:
		if err = a.passwdLoginPost1(); err != nil {
			return "", fmt.Errorf("passwd login post1 failed: %v", err)
		}
	case TYPE_EMAIL:
		cookies, err = a.emailLoginPost1()
		if err != nil {
			return "", fmt.Errorf("email login post1 failed: %v", err)
		}
		return cookies, fmt.Errorf("email login need code to continue")
	case TYPE_DEVICE:
		cookies, code, err := a.deviceLoginPost1()
		if err != nil {
			return "", fmt.Errorf("device login post1 failed: %v", err)
		}
		return cookies, fmt.Errorf("device login need handler to continue, code: %s", code)
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
	if err = a.deviceLoginPost2(); err != nil {
		return "", fmt.Errorf("device login post2 failed: %v", err)
	}
	if err = a.deviceLoginPost3(); err != nil {
		return "", fmt.Errorf("device login post3 failed: %v", err)
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
	return a.LoginType
}

func getValue(s string) string {
	return strings.Split(s, "'")[1]
}

func (a *AuthStruct) findHtmlValue(n *html.Node) (node *html.Node) {
	if n.Type == html.ElementNode && n.Data == "form" {
		for _, v := range n.Attr {
			if v.Key == "action" {
				a.ActionUrl = v.Val
			}
		}
	}
	if n.Type == html.ElementNode && n.Data == "input" {
		for _, v := range n.Attr {
			if v.Key == "id" && v.Val == "NAPExp" {
				for _, v := range n.Attr {
					if v.Key == "value" {
						a.PassportData.NAPExp = v.Val
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
						a.PassportData.PPRID = v.Val
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
						a.PassportData.NAP = v.Val
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
						a.PassportData.ANON = v.Val
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
						a.PassportData.ANONExp = v.Val
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
						a.PassportData.T = v.Val
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
