package bingauth

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func (a *AuthStruct) keepLoginPost() (err error) {
	postdata := url.Values{}
	postdata.Add("LoginOptions", "1")
	postdata.Add("type", "28")
	postdata.Add("ctx", "")
	postdata.Add("hpgrequestid", "")
	postdata.Add("PPFT", a.ppft)
	postdata.Add("canary", "")

	// 保持登录 => https://login.live.com/ppsecure/post.srf
	a.reqClient.Post().SetUrl("%v", a.urlPost).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()

	if a.reqClient.GetStatusCode() != 200 {
		return fmt.Errorf("login post failed, status code: %v", a.reqClient.Result.Status)
	}

	body, err := html.Parse(bytes.NewReader(a.reqClient.GetBody()))
	if err != nil {
		return
	}

	a.findHtmlValue(body)

	return nil
}
