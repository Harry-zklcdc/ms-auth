package bingauth

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

func (a *AuthStruct) emailLoginPost2(code string) (err error) {
	postData := url.Values{}
	postData.Add("SentProofIDE", a.CredentialType.Credentials.OtcLoginEligibleProofs[0].Data)
	postData.Add("ProofConfirmation", a.Account)
	postData.Add("ps", "3")
	postData.Add("psRNGCDefaultType", "")
	postData.Add("psRNGCEntropy", "")
	postData.Add("psRNGCSLK", "")
	postData.Add("canary", "")
	postData.Add("ctx", "")
	postData.Add("hpgrequestid", "")
	postData.Add("PPFT", a.FlowToken)
	postData.Add("PPSX", "Passpor")
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
	postData.Add("type", "27")
	postData.Add("LoginOptions", "3")
	postData.Add("lrt", "")
	postData.Add("lrtPartition", "")
	postData.Add("hisRegion", "")
	postData.Add("hisScaleUnit", "")
	postData.Add("otc", code)

	// 输入验证码 => https://login.live.com/ppsecure/post.srf?contextid=
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
