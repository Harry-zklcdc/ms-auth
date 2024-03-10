package bingauth

import (
	"encoding/json"
	"net/url"
	"strings"
)

type emailLoginPost1Resp struct {
	FlowToken string `json:"flowToken"`
	Status    int    `json:"status"`
}

func (a *AuthStruct) emailLoginPost1() (cookies string, err error) {
	postdata := url.Values{}
	postdata.Set("login", a.Account)
	postdata.Set("flowtoken", a.FlowToken)
	postdata.Set("purpose", "eOTT_OtcLogin")
	postdata.Set("channel", "Email")
	postdata.Set("AltEmailE", a.CredentialType.Credentials.OtcLoginEligibleProofs[0].Data)
	postdata.Set("lcid", a.Lcid)
	postdata.Set("uaid", a.Uaid)
	postdata.Set("ProofConfirmation", a.Account)
	postdata.Set("ChallengeViewSupported", "true")

	// 发送邮件验证码 => https://login.live.com/GetOneTimeCode.srf?lcid=2052&id=264960&nopa=2
	a.reqClient.Post().
		SetUrl("https://login.live.com/GetOneTimeCode.srf?lcid=%s&id=%s&nopa=2", a.Lcid, a.Id).
		SetContentType("application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()

	var resp emailLoginPost1Resp
	err = json.Unmarshal(a.reqClient.GetBody(), &resp)
	if err != nil {
		return
	}
	a.Ppft = resp.FlowToken

	for _, v := range a.reqClient.Cookies {
		values := strings.Split(v.Value, ";")
		cookies += v.Name + "=" + values[0] + "; "
	}
	cookies = strings.Trim(cookies, "; ")

	return
}
