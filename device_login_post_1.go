package bingauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

func (a *AuthStruct) deviceLoginPost1() (err error) {
	postdata := map[string]any{
		"DeviceCode": a.credentialType.Credentials.RemoteNgcParams.SessionIdentifier,
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
			SetUrl("https://login.live.com/GetSessionState.srf?nopa=2&cobrandid=c333cba8-c15c-4458-b082-7c8ce81bee85&id=%s&mkt=ZH-CN&lc=%s&uaid=%s&slk=%s&slkt=NGC", a.id, a.lcid, a.uaid, a.credentialType.Credentials.RemoteNgcParams.SessionIdentifier).
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
