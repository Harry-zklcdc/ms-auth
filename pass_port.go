package bingauth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Harry-zklcdc/bing-lib/lib/hex"
	"github.com/Harry-zklcdc/bing-lib/lib/request"
)

func (a *AuthStruct) passport() (cookie string, err error) {
	a.reqClient = request.NewRequest().SetUserAgent(USER_AGENT)

	a.reqClient.Get().SetUrl("https://www.bing.com/").Do()
	if a.reqClient.GetStatusCode() != 200 {
		return "", fmt.Errorf("passport failed, status code: %v", a.reqClient.Result.Status)
	}

	postdata := url.Values{}
	postdata.Add("url", "https://www.bing.com/")
	postdata.Add("V", "web")

	a.reqClient.Post().SetUrl("https://www.bing.com/rewardsapp/reportActivity?IG=%s&IID=SERP.5026&&src=hp", strings.ToUpper(strings.ReplaceAll(hex.NewUUID(), "-", ""))).
		SetContentType("application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()
	if a.reqClient.GetStatusCode() != 200 {
		return "", fmt.Errorf("passport failed, status code: %v", a.reqClient.Result.Status)
	}

	postdata = url.Values{}
	postdata.Add("NAPExp", a.PassportData.NAPExp)
	postdata.Add("pprid", a.PassportData.PPRID)
	postdata.Add("NAP", a.PassportData.NAP)
	postdata.Add("ANON", a.PassportData.ANON)
	postdata.Add("ANONExp", a.PassportData.ANONExp)
	postdata.Add("t", a.PassportData.T)

	a.reqClient.Post().SetUrl("%v", a.ActionUrl).
		SetContentType("application/x-www-form-urlencoded").
		SetHeader("Origin", "https://login.live.com").
		SetHeader("Referer", "https://login.live.com/").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()

	if a.reqClient.GetStatusCode() != 200 {
		return "", fmt.Errorf("passport failed, status code: %v", a.reqClient.Result.Status)
	}

	for _, v := range a.reqClient.Cookies {
		values := strings.Split(v.Value, ";")
		cookie += v.Name + "=" + values[0] + "; "
	}
	cookie = strings.Trim(cookie, "; ")
	return
}
