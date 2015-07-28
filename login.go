package oauthexample

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/net/context"

	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"

	"github.com/nu7hatch/gouuid"
)

const redirectURI = "http://localhost:8080/oauth2callback"

func init() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/dropbox-login", handleDropboxLogin)
	http.HandleFunc("/oauth2callback", handleOauth2Callback)
}

func handleIndex(res http.ResponseWriter, req *http.Request) {
	io.WriteString(res, `<!DOCTYPE html>
<html>
  <head></head>
  <body>
    <a href="/dropbox-login">LOGIN WITH DROPBOX</a>
  </body>
</html>`)
}

func handleDropboxLogin(res http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	// get the session
	session := getSession(ctx, req)
	id, _ := uuid.NewV4()

	values := make(url.Values)
	values.Add("response_type", "code")
	values.Add("client_id", "vmqwbq2tj8l57k9")
	values.Add("redirect_uri", redirectURI)
	values.Add("state", id.String())

	// save the session
	session.State = id.String()
	putSession(ctx, res, session)

	http.Redirect(res, req, fmt.Sprintf(
		"https://www.dropbox.com/1/oauth2/authorize?%s",
		values.Encode(),
	), 302)
}

func handleOauth2Callback(res http.ResponseWriter, req *http.Request) {
	ctx := appengine.NewContext(req)
	// get the session
	session := getSession(ctx, req)

	state := req.FormValue("state")
	code := req.FormValue("code")

	if state != session.State {
		http.Error(res, "invalid state", 401)
		return
	}

	accessToken, err := getAccessToken(ctx, state, code)
	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}

	email, err := getEmail(ctx, accessToken)
	if err != nil {
		http.Error(res, err.Error(), 500)
		return
	}

	session.Email = email
	putSession(ctx, res, session)

	fmt.Fprintln(res, email)

}

func getEmail(ctx context.Context, accessToken string) (string, error) {
	client := urlfetch.Client(ctx)
	response, err := client.Get(
		"https://api.dropbox.com/1/account/info?access_token=" + accessToken)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	var data struct {
		UID int `json:"uid"`
	}
	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(data.UID), nil
}

func getAccessToken(ctx context.Context, state, code string) (string, error) {
	values := make(url.Values)
	values.Add("client_id", "vmqwbq2tj8l57k9")
	values.Add("client_secret", "rpcztciueyunhba")
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("redirect_uri", redirectURI)

	client := urlfetch.Client(ctx)
	response, err := client.PostForm("https://api.dropbox.com/1/oauth2/token", values)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	bs, _ := ioutil.ReadAll(response.Body)

	var data struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		UID         string `json:"uid"`
	}
	err = json.Unmarshal(bs, &data)
	if err != nil {
		return "", err
	}
	if data.AccessToken == "" {
		return "", fmt.Errorf("Invalid Access Token:%s", string(bs))
	}
	return data.AccessToken, nil
}
