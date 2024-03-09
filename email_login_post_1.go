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

func (a *AuthStruct) emailLoginPost1() (err error) {
	postdata := url.Values{}
	postdata.Set("login", a.account)
	postdata.Set("flowtoken", a.flowToken)
	postdata.Set("purpose", "eOTT_OtcLogin")
	postdata.Set("channel", "Email")
	postdata.Set("AltEmailE", a.credentialType.Credentials.OtcLoginEligibleProofs[0].Data)
	postdata.Set("lcid", a.lcid)
	postdata.Set("uaid", a.uaid)
	postdata.Set("ProofConfirmation", a.account)
	postdata.Set("ChallengeViewSupported", "true")

	// 发送邮件验证码 => https://login.live.com/GetOneTimeCode.srf?lcid=2052&id=264960&nopa=2
	a.reqClient.Post().
		SetUrl("https://login.live.com/GetOneTimeCode.srf?lcid=%s&id=%s&nopa=2", a.lcid, a.id).
		SetContentType("application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postdata.Encode())).
		Do()

	var resp emailLoginPost1Resp
	err = json.Unmarshal(a.reqClient.GetBody(), &resp)
	if err != nil {
		return
	}
	a.ppft = resp.FlowToken
	return
}
