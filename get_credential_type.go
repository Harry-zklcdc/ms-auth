package bingauth

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type getCredentialTypeReq struct {
	CheckPhones                    bool   `json:"checkPhones"`
	Country                        string `json:"country"`
	FederationFlags                int    `json:"federationFlags"`
	FlowToken                      string `json:"flowToken"`
	Forceotclogin                  bool   `json:"forceotclogin"`
	IsCookieBannerShown            bool   `json:"isCookieBannerShown"`
	IsExternalFederationDisallowed bool   `json:"isExternalFederationDisallowed"`
	IsFederationDisabled           bool   `json:"isFederationDisabled"`
	IsFidoSupported                bool   `json:"isFidoSupported"`
	IsOtherIdpSupported            bool   `json:"isOtherIdpSupported"`
	IsRemoteConnectSupported       bool   `json:"isRemoteConnectSupported"`
	IsRemoteNGCSupported           bool   `json:"isRemoteNGCSupported"`
	IsSignup                       bool   `json:"isSignup"`
	OriginalRequest                string `json:"originalRequest"`
	Otclogindisallowed             bool   `json:"otclogindisallowed"`
	Uaid                           string `json:"uaid"`
	Username                       string `json:"username"`
}

type getCredentialTypeResp struct {
	AliasDisabledForLogin bool `json:"AliasDisabledForLogin"`
	Credentials           struct {
		CobasiApp              bool `json:"CobasiApp"`
		HasFido                int  `json:"HasFido"`
		HasGitHubFed           int  `json:"HasGitHubFed"`
		HasGoogleFed           int  `json:"HasGoogleFed"`
		HasLinkedInFed         int  `json:"HasLinkedInFed"`
		HasPassword            int  `json:"HasPassword"`
		HasPhone               int  `json:"HasPhone"`
		HasRemoteNGC           int  `json:"HasRemoteNGC"`
		OTCNotAutoSent         int  `json:"OTCNotAutoSent"`
		PrefCredential         int  `json:"PrefCredential"`
		OtcLoginEligibleProofs []struct {
			Data string `json:"data"`
		} `json:"OtcLoginEligibleProofs"`
		RemoteNgcParams struct {
			SessionIdentifier string `json:"SessionIdentifier"`
			Entropy           string `json:"Entropy"`
		} `json:"RemoteNgcParams"`
	} `json:"Credentials"`
	Display        string `json:"Display"`
	IfExistsResult int    `json:"IfExistsResult"`
	Location       string `json:"Location"`
	Username       string `json:"Username"`
}

func (a *AuthStruct) getCredentialType() (err error) {
	reqBody := getCredentialTypeReq{
		CheckPhones:                    false,
		Country:                        "",
		FederationFlags:                3,
		FlowToken:                      a.flowToken,
		Forceotclogin:                  false,
		IsCookieBannerShown:            false,
		IsExternalFederationDisallowed: false,
		IsFederationDisabled:           false,
		IsFidoSupported:                false,
		IsOtherIdpSupported:            true,
		IsRemoteConnectSupported:       false,
		IsRemoteNGCSupported:           true,
		IsSignup:                       false,
		OriginalRequest:                "",
		Otclogindisallowed:             false,
		Uaid:                           a.uaid,
		Username:                       a.account,
	}

	switch a.loginType {
	case TYPE_DEVICE:
		reqBody.IsFidoSupported = true
	}

	reqB, err := json.Marshal(reqBody)
	if err != nil {
		return
	}
	a.reqClient.Post().SetUrl(a.urlGetCredentialType).
		SetHeader("Content-Type", "application/json").
		SetBody(bytes.NewReader(reqB)).
		Do()
	if a.reqClient.GetStatusCode() != 200 {
		return fmt.Errorf("get credential type failed, status code: %v", a.reqClient.GetStatusCode())
	}
	// fmt.Println(a.reqClient.GetStatusCode())
	// fmt.Println(a.reqClient.GetBodyString())

	err = json.Unmarshal(a.reqClient.GetBody(), &a.credentialType)
	if err != nil {
		return
	}
	return nil
}
