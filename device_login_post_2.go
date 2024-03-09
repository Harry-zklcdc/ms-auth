package bingauth

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

func (a *AuthStruct) deviceLoginPost2() (err error) {
	postData := url.Values{}
	postData.Add("slk", a.credentialType.Credentials.RemoteNgcParams.SessionIdentifier)
	postData.Add("ps", "4")
	postData.Add("psRNGCDefaultType", "1")
	postData.Add("psRNGCEntropy", "")
	postData.Add("psRNGCSLK", a.credentialType.Credentials.RemoteNgcParams.SessionIdentifier)
	postData.Add("canary", "")
	postData.Add("ctx", "")
	postData.Add("hpgrequestid", "")
	postData.Add("PPFT", a.flowToken)
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
	postData.Add("login", a.account)
	postData.Add("loginfmt", a.account)
	postData.Add("type", "21")
	postData.Add("LoginOptions", "3")
	postData.Add("lrt", "")
	postData.Add("lrtPartition", "")
	postData.Add("hisRegion", "")
	postData.Add("hisScaleUnit", "")

	// 2FA验证 => https://login.live.com/ppsecure/post.srf?contextid=
	a.reqClient.Post().SetUrl("%v", a.urlPostMsa).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(strings.NewReader(postData.Encode())).
		Do()

	if a.reqClient.GetStatusCode() != 200 {
		return fmt.Errorf("login post failed, status code: %v", a.reqClient.Result.Status)
	}

	// fmt.Println(a.reqClient.GetBodyString())

	re := regexp.MustCompile(regUrlPost)
	a.urlPost = getValue(re.FindString(a.reqClient.GetBodyString()))

	re = regexp.MustCompile(regPPFT)
	a.ppft = getValue(re.FindString(a.reqClient.GetBodyString()))

	return nil
}
