package bingauth

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Harry-zklcdc/bing-lib/lib/hex"
)

func (a *AuthStruct) getSession() (err error) {
	bUrl, _ := url.Parse("https://login.live.com/login.srf")

	query := bUrl.Query()
	query.Add("wa", "wsignin1.0")
	query.Add("rpsnv", "22")
	query.Add("id", "264960")
	query.Add("wp", "MBI_SSL")
	query.Add("lc", "2052")
	query.Add("CSRFToken", hex.NewUUID())
	query.Add("cobrandid", hex.NewUUID())
	query.Add("aadredir", "1")
	query.Add("nopa", "2")
	query.Add("wreply", "https://www.bing.com/secure/Passport.aspx?edge_suppress_profile_switch=1&requrl=https%3a%2f%2fwww.bing.com%2f%3fwlexpsignin%3d1&sig=34EFE4ED9C94667A1B55F0D09D9C6732&nopa=2")

	bUrl.RawQuery = query.Encode()

	a.reqClient.Get().SetUrl("%v", bUrl.String()).Do()

	if a.reqClient.GetStatusCode() != 200 {
		return fmt.Errorf("get session failed, status code: %v", a.reqClient.Result.Status)
	}

	re := regexp.MustCompile(regUrlGetCredentialType)
	a.urlGetCredentialType = getValue(re.FindString(a.reqClient.GetBodyString()))

	tmpUrl, _ := url.Parse(a.urlGetCredentialType)
	a.uaid = tmpUrl.Query().Get("uaid")
	a.id = tmpUrl.Query().Get("id")
	a.lcid = tmpUrl.Query().Get("lc")
	a.cobrandid = tmpUrl.Query().Get("cobrandid")

	re = regexp.MustCompile(regUrlPostMsa)
	a.urlPostMsa = getValue(re.FindString(a.reqClient.GetBodyString()))

	re = regexp.MustCompile(regSFTTag)
	tmp := getValue(re.FindString(a.reqClient.GetBodyString()))
	re = regexp.MustCompile(regValue)
	a.flowToken = strings.Split(re.FindString(tmp), "\"")[1]

	re = regexp.MustCompile(regUrlSessionState)
	a.urlSessionState = getValue(re.FindString(a.reqClient.GetBodyString()))

	return nil
}
