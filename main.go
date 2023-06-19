package main

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zserge/lorca"
)

// const portalUrl = "https://vpn.company.com"
// const portalPreloginUrl = portalUrl + "/global-protect/prelogin.esp?tmp=tmp&kerberos-support=yes&ipv6-support=yes&clientVer=4100&clientos=Linux"

var gatewayUrl = flag.String("gateway", "", "Gateway URL (eg: dublin-1.vpn.company.com)")
var userName = flag.String("username", "1234", "username for auto input")
var passWord = flag.String("password", "1234", "password for auto input")

type SAMLPreloginData struct {
	Status         uint   `xml:"saml-auth-status"`
	PreloginCookie string `xml:"prelogin-cookie"`
	Username       string `xml:"saml-username"`
}

func gpHTTPPostForm(u string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", "PAN GlobalProtect")
	return http.DefaultClient.Do(req)
}

// InitPrelogin returns the SAML HTML snippet needed to start the prelogin
// step.
func InitPrelogin() (string, error) {
	type xmlResponse struct {
		Status         string `xml:"status"`
		Region         string `xml:"region"`
		SAMLAuthMethod string `xml:"saml-auth-method"`
		SAMLRequest    string `xml:"saml-request"`
	}

	var response xmlResponse

	preloginUrl := "https://" + *gatewayUrl + "/ssl-vpn/prelogin.esp?tmp=tmp&kerberos-support=yes&ipv6-support=yes&clientVer=4100&clientos=Linux"
	err := PostReq(nil, preloginUrl, &response)
	if err != nil {
		return "", err
	}

	if response.Status != "Success" {
		return "", fmt.Errorf("InitPrelogin: bad status %s", response.Status)
	}
	if response.SAMLAuthMethod != "POST" {
		return "", fmt.Errorf("InitPrelogin: unsupported SAML auth method %s", response.SAMLAuthMethod)
	}

	decoded, err := base64.StdEncoding.DecodeString(response.SAMLRequest)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func Prelogin(samlPreloginHTML string) (*SAMLPreloginData, error) {
	os.RemoveAll("./data/Default/Preferences")
	ui, err := lorca.New(`data:text/html,`+url.PathEscape(samlPreloginHTML), "./data", 500, 800, "--remote-allow-origins=*")
	if err != nil {
		return nil, err
	}
  js_autoinput := fmt.Sprintf(`document.getElementById("userNameInput").value='%s';document.getElementById("passwordInput").value='%s'`, *userName, *passWord)
  ui.Eval(js_autoinput)
	defer ui.Close()

	// A trick to get back the SAML payload we got from the browser response
	var preloginCookie *SAMLPreloginData
	ui.Bind("storeSamlPreloginXML", func(xmlStr string) {
		var cookie SAMLPreloginData
		xml.Unmarshal([]byte("<wrapper>"+xmlStr+"</wrapper>"), &cookie)
		preloginCookie = &cookie
	})

	wg := sync.WaitGroup{}
	wg.Add(2)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
				ui.Eval(`
						(() => {
							const ni = document.createNodeIterator(document.getRootNode(), NodeFilter.SHOW_COMMENT);
							const comment = ni.nextNode();
							if (comment && /saml-auth-status/.test(comment.textContent)) {
								storeSamlPreloginXML(comment.textContent);
							}
						})();
					`)
				if preloginCookie != nil {
					ui.Close()
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()

		<-ui.Done()
		cancel()
	}()

	wg.Wait()

	if preloginCookie == nil {
		return nil, fmt.Errorf("Prelogin: prelogin cookie could not be fetched")
	}

	return preloginCookie, nil
}

func PostReq(preloginData *SAMLPreloginData, u string, x interface{}) error {
	values := make(url.Values)

	if preloginData != nil {
		values.Add("prot", "https:")
		values.Add("clientVer", "4100")
		values.Add("clientos", "Linux")
		values.Add("ipv6-support", "yes")
		values.Add("os-version", "linux")
		values.Add("prelogin-cookie", preloginData.PreloginCookie)
		values.Add("user", preloginData.Username)
		values.Add("server", "")
		values.Add("inputSrc", "")
		values.Add("jnlpReady", "jnlpReady")
		values.Add("passwd", "")
		values.Add("computer", "machine")
		values.Add("ok", "Login")
		values.Add("direct", "yes")
		values.Add("portal-prelogonuserauthcookie", "")
		values.Add("portal-userauthcookie", "")
	}

	res, err := gpHTTPPostForm(u, values)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("PostReq: bad status %d", res.StatusCode)
	}
	if res.Body == nil {
		return fmt.Errorf("PostReq: no body returned")
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// log.Printf("BODY: (url=%s)\n", u)
	// log.Println(string(body))
	// log.Println("---")

	if x != nil {
		err = xml.Unmarshal(body, x)
		if err != nil {
			return err
		}
	}

	return nil
}

func Login(preloginCookie SAMLPreloginData) (string, error) {
	type appDesc struct {
		Args []string `xml:"argument"`
	}
	type xmlResponse struct {
		AppDesc appDesc `xml:"application-desc"`
	}

	var xmlRes xmlResponse
	loginUrl := "https://" + *gatewayUrl + "/ssl-vpn/login.esp"
	err := PostReq(&preloginCookie, loginUrl, &xmlRes)
	if err != nil {
		return "", err
	}

	cookie := make(url.Values)
	cookie.Add("authcookie", xmlRes.AppDesc.Args[1])
	cookie.Add("portal", xmlRes.AppDesc.Args[3])
	cookie.Add("user", xmlRes.AppDesc.Args[4])
	cookie.Add("domain", xmlRes.AppDesc.Args[7])
	cookie.Add("computer", "machine")

	return cookie.Encode(), nil
}

// func Config(preloginCookie SAMLPreloginData) error {
// 	return PostReq(&preloginCookie, portalUrl + "/global-protect/getconfig.esp", nil)
// }

func main() {
	flag.Parse()

	if gatewayUrl == nil || *gatewayUrl == "" {
		flag.Usage()
		os.Exit(1)
	}

	samlPreloginHTML, err := InitPrelogin()
	if err != nil {
		log.Fatalf("prelogin initialization failed : %s", err)
	}

	samlPreloginData, err := Prelogin(samlPreloginHTML)
	if err != nil {
		log.Fatalf("prelogin flow failed : %s", err)
	}

	openConnectUserAuthCookie, err := Login(*samlPreloginData)
	if err != nil {
		log.Fatalf("login failed : %s", err)
	}

	fmt.Println(openConnectUserAuthCookie)

	// fmt.Printf(Config(*preloginCookie))
}
