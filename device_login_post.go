package bingauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type deviceLoginPost1Resp struct {
	FlowToken        string `json:"flowToken"`
	DisplaySignForUI string `json:"displaySignForUI"`
	Status           int    `json:"status"`
}

func (a *AuthStruct) deviceLoginPost1() (cookies, code string, err error) {
	postdata := url.Values{}
	postdata.Set("login", a.Account)
	postdata.Set("flowtoken", a.CredentialType.Credentials.RemoteNgcParams.SessionIdentifier)
	postdata.Set("purpose", "eOTT_RemoteNGC")
	postdata.Set("channel", "PushNotifications")
	postdata.Set("SAPId", "")
	postdata.Set("lcid", a.Lcid)
	postdata.Set("uaid", a.Uaid)
	postdata.Set("canaryFlowToken", a.FlowToken)

	// 发送2FA验证码 => https://login.live.com/GetOneTimeCode.srf?lcid=2052&id=264960&nopa=2
	a.reqClient.Post().
		SetUrl("https://login.live.com/GetOneTimeCode.srf?lcid=%s&id=%s&nopa=2", a.Lcid, a.Id).
		SetContentType("application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()

	// fmt.Println(a.reqClient.GetBodyString())

	var resp deviceLoginPost1Resp
	err = json.Unmarshal(a.reqClient.GetBody(), &resp)
	if err != nil {
		return
	}

	a.Ppft = resp.FlowToken
	if resp.Status == 201 {
		code = resp.DisplaySignForUI
	} else {
		code = a.CredentialType.Credentials.RemoteNgcParams.Entropy
	}

	// fmt.Println(a.reqClient.GetBodyString())

	for _, v := range a.reqClient.Cookies {
		values := strings.Split(v.Value, ";")
		cookies += v.Name + "=" + values[0] + "; "
	}
	cookies = strings.Trim(cookies, "; ")

	return
}

func (a *AuthStruct) deviceLoginPost2() (err error) {
	postdata := map[string]any{
		"DeviceCode": a.CredentialType.Credentials.RemoteNgcParams.SessionIdentifier,
	}
	d, err := json.Marshal(postdata)
	if err != nil {
		return
	}

	resp := struct {
		AuthorizationState int `json:"AuthorizationState"`
		SessionState       int `json:"SessionState"`
	}{}

	i := 0
	for i = 0; i < 60; i++ {
		a.reqClient.Post().
			SetUrl("https://login.live.com/GetSessionState.srf?nopa=2&cobrandid=c333cba8-c15c-4458-b082-7c8ce81bee85&id=%s&mkt=ZH-CN&lc=%s&uaid=%s&slk=%s&slkt=NGC", a.Id, a.Lcid, a.Uaid, a.CredentialType.Credentials.RemoteNgcParams.SessionIdentifier).
			SetContentType("application/json").
			SetHeader("Accept", "application/json").
			SetBody(bytes.NewReader(d)).
			Do()

		err = json.Unmarshal(a.reqClient.GetBody(), &resp)
		if err != nil {
			return err
		}
		if resp.AuthorizationState == 2 && resp.SessionState == 2 {
			break
		}
		if resp.SessionState == 3 {
			return fmt.Errorf("device login failed")
		}

		time.Sleep(1 * time.Second)
	}
	if i >= 60 {
		return fmt.Errorf("device login timeout")
	}

	return
}

func (a *AuthStruct) deviceLoginPost3() (err error) {
	postData := url.Values{}
	postData.Add("slk", a.CredentialType.Credentials.RemoteNgcParams.SessionIdentifier)
	postData.Add("ps", "4")
	postData.Add("psRNGCDefaultType", "1")
	postData.Add("psRNGCEntropy", "")
	postData.Add("psRNGCSLK", a.CredentialType.Credentials.RemoteNgcParams.SessionIdentifier)
	postData.Add("canary", "")
	postData.Add("ctx", "")
	postData.Add("hpgrequestid", "")
	postData.Add("PPFT", a.FlowToken)
	postData.Add("PPSX", "P")
	postData.Add("NewUser", "1")
	postData.Add("FoundMSAs", "")
	postData.Add("fspost", "0")
	postData.Add("i21", "0")
	postData.Add("CookieDisclosure", "0")
	postData.Add("IsFidoSupported", "1")
	postData.Add("isSignupPost", "0")
	postData.Add("isRecoveryAttemptPost", "0")
	postData.Add("i13", "0")
	postData.Add("login", a.Account)
	postData.Add("loginfmt", a.Account)
	postData.Add("type", "21")
	postData.Add("LoginOptions", "3")
	postData.Add("lrt", "")
	postData.Add("lrtPartition", "")
	postData.Add("hisRegion", "")
	postData.Add("hisScaleUnit", "")

	// 2FA验证 => https://login.live.com/ppsecure/post.srf?contextid=
	a.reqClient.Post().SetUrl("%v", a.UrlPostMsa).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postData.Encode())).
		Do()

	if a.reqClient.GetStatusCode() != 200 {
		return fmt.Errorf("login post failed, status code: %v", a.reqClient.Result.Status)
	}

	// fmt.Println(a.reqClient.GetBodyString())

	re := regexp.MustCompile(regUrlPost)
	a.UrlPost = getValue(re.FindString(a.reqClient.GetBodyString()))

	re = regexp.MustCompile(regPPFT)
	a.Ppft = getValue(re.FindString(a.reqClient.GetBodyString()))

	return nil
}
