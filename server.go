/**
 * @author: yangchangjia
 * @email 1320259466@qq.com
 * @date: 2024/4/22 15:00
 * @desc: about the role of class.
 */

package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AbnerEarl/goutils/httpc"
	"github.com/AbnerEarl/goutils/redisc"
	"github.com/AbnerEarl/sso/oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"time"
)

type OidcConfig struct {
	OidcProvider string
	*oauth2.Config
	AppTopDomain    []string
	CookieMaxAge    int
	RedisClusterCli *redisc.RedisClusterCli // A redis cluster is recommended for production environments to synchronize user information.
	RedisCli        *redisc.RedisCli        // Test environments can use redis single node to synchronize user information.
}

type TokenInfo struct {
	*oauth2.Token
	*oidc.IDToken
}

type UserInfo struct {
	//*server.IdTokenClaims
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          string   `json:"aud"`
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	AuthorizingParty  string   `json:"azp,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	AccessTokenHash   string   `json:"at_hash,omitempty"`
	CodeHash          string   `json:"c_hash,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
}

func GetFunctionName(fun interface{}, seps ...rune) string {
	// 获取函数名称
	fn := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
	// 用 seps 进行分割
	fields := strings.FieldsFunc(fn, func(sep rune) bool {
		for _, s := range seps {
			if sep == s {
				return true
			}
		}
		return false
	})

	size := len(fields)
	if size > 1 {
		return fields[size-2]
	} else if size > 0 {
		return fields[size-1]
	}
	return ""
}

func (o *OidcConfig) ExecuteRdb(fun interface{}, params ...interface{}) (string, error) {
	var obj reflect.Value
	if o.RedisClusterCli != nil {
		obj = reflect.ValueOf(o.RedisClusterCli)
	} else if o.RedisCli != nil {
		obj = reflect.ValueOf(o.RedisCli)
	} else {
		panic("No redis connection configured, initialize \"RedisCli: redisc.InitRedis()\" or \"RedisClusterCli: redisc.InitRedisCluster() \".")
	}
	fn := GetFunctionName(fun, '-', '.')
	method := obj.MethodByName(fn)
	if !method.IsValid() {
		return "", fmt.Errorf("method not found: %s", fun)
	}
	//if method.Type().IsVariadic() {
	//	method = method.MethodByName(fn)
	//}
	var args []reflect.Value
	for _, p := range params {
		args = append(args, reflect.ValueOf(p))
	}

	values := method.Call(args)

	if len(values) == 0 {
		return "", nil
	}
	if len(values) < 2 {
		return "", fmt.Errorf("%v", values[0].Interface())
	}
	if values[1].Interface() != nil {
		return fmt.Sprintf("%s", values[0].Interface()), fmt.Errorf("%v", values[1].Interface())
	}
	return fmt.Sprintf("%s", values[0].Interface()), nil

}

func (o *OidcConfig) LoginHandler(w http.ResponseWriter, r *http.Request) {
	_, err := o.GetToken(w, r)
	if err == nil {
		http.Redirect(w, r, "/user", http.StatusFound)
	} else {
		url := o.AuthCodeURL("state", oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func (o *OidcConfig) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	_, err := o.GetToken(w, r)
	if err == nil {
		http.Redirect(w, r, "/user", http.StatusFound)
	} else {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		token, err := o.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		o.SetTokenIntoCookie(w, r, token, "", o.CookieMaxAge)

		http.Redirect(w, r, "/user", http.StatusFound)
	}
}

func (o *OidcConfig) UserHandler(w http.ResponseWriter, r *http.Request) {
	//accessToken := r.URL.Query().Get("access_token")
	info, err := o.GetUserInfo(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bys, err := json.Marshal(info)
	w.Write(bys)
}

func (o *OidcConfig) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	o.DelTokenIntoCookie(w, r)
	info := map[string]interface{}{
		"result":  "success",
		"message": "the user logout",
	}
	bys, _ := json.Marshal(info)
	w.Write(bys)
}

func (o *OidcConfig) RefreshToken(w http.ResponseWriter, r *http.Request) error {
	refreshToken, err := o.GetValue(w, r, "refresh_token")
	if err != nil {
		return fmt.Errorf("get refresh_token from request failed: %v", err)
	}
	ts := o.TokenSource(context.Background(), &oauth2.Token{RefreshToken: refreshToken})
	newToken, err := ts.Token()
	if err != nil {
		return fmt.Errorf("refresh token failed: %v", err)
	}
	o.SetTokenIntoCookie(w, r, newToken, "", o.CookieMaxAge)
	return nil
}

func (o *OidcConfig) VerifyToken(w http.ResponseWriter, r *http.Request) error {
	rawIDToken, err := o.GetToken(w, r)
	if err != nil {
		return fmt.Errorf("get id_token from request failed: %v", err)
	}

	accessToken, err := o.GetValue(w, r, "access_token")
	if err != nil {
		return fmt.Errorf("get access_token from request failed: %v", err)
	}

	provider, err := oidc.NewProvider(context.Background(), o.OidcProvider)
	if err != nil {
		return fmt.Errorf("init oidc provider failed: %v", err)
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: o.ClientID})
	idToken, err := idTokenVerifier.Verify(context.Background(), rawIDToken)
	// check if id_token matches access_token
	if err = idToken.VerifyAccessToken(accessToken); err != nil {
		return fmt.Errorf("id_token does not match access_token")

	}
	return nil
}

func (o *OidcConfig) SetTokenIntoCookie(w http.ResponseWriter, r *http.Request, oauth2Token *oauth2.Token, cookieDomain string, maxAge int) {
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	cookies := []*http.Cookie{
		{Name: "access_token", Value: oauth2Token.AccessToken},
		{Name: "token_type", Value: oauth2Token.TokenType},
		{Name: "refresh_token", Value: oauth2Token.RefreshToken},
		{Name: "expiry", Value: oauth2Token.Expiry.Format(time.RFC3339)},
		{Name: "id_token", Value: rawIDToken},
	}

	fingerprint := httpc.GenerateFingerprint(r)

	for _, c := range cookies {
		if len(cookieDomain) > 4 {
			c.Domain = cookieDomain
		}
		c.Path = "/"
		if maxAge > 0 {
			c.MaxAge = maxAge
		} else {
			c.MaxAge = 60 * 5
		}
		c.HttpOnly = true
		bys, _ := json.Marshal(c)
		_, err := o.ExecuteRdb(o.RedisCli.RdbHSet, fingerprint, c.Name, bys)
		if err != nil {
			http.SetCookie(w, c)
		}
	}
}

func (o *OidcConfig) SyncTokenIntoCookie(w http.ResponseWriter, r *http.Request, cookieDomain string, maxAge int) {
	accessToken, _ := o.GetCookieFromRDB(r, "access_token")
	tokenType, _ := o.GetCookieFromRDB(r, "token_type")
	refreshToken, _ := o.GetCookieFromRDB(r, "refresh_token")
	expiry, _ := o.GetCookieFromRDB(r, "expiry")
	idToken, _ := o.GetCookieFromRDB(r, "id_token")
	cookies := []*http.Cookie{
		&accessToken,
		&tokenType,
		&refreshToken,
		&expiry,
		&idToken,
	}

	for _, c := range cookies {
		if len(cookieDomain) > 4 {
			c.Domain = cookieDomain
		}
		if maxAge > 0 {
			c.MaxAge = maxAge
		} else {
			c.MaxAge = 60 * 5
		}
		http.SetCookie(w, c)
	}
}

func (o *OidcConfig) DelTokenIntoCookie(w http.ResponseWriter, r *http.Request) {
	cookies := []*http.Cookie{
		{Name: "access_token", MaxAge: -1},
		{Name: "token_type", MaxAge: -1},
		{Name: "refresh_token", MaxAge: -1},
		{Name: "expiry", MaxAge: -1},
		{Name: "id_token", MaxAge: -1},
	}
	fingerprint := httpc.GenerateFingerprint(r)
	for _, c := range cookies {
		http.SetCookie(w, c)
		w.Header().Del(c.Name)
		o.ExecuteRdb(o.RedisCli.RdbHDel, fingerprint, c.Name)
	}

}

func (o *OidcConfig) GetTokenInfo(w http.ResponseWriter, r *http.Request) (*TokenInfo, error) {
	// verify IDToken with idTokenVerifier, the idTokenVerifier is generated by provider
	provider, err := oidc.NewProvider(context.Background(), o.OidcProvider)
	if err != nil {
		return nil, fmt.Errorf("init oidc provider failed: %v", err)

	}
	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: o.ClientID})
	rawIDToken, err := o.GetToken(w, r)
	if err != nil {
		return nil, fmt.Errorf("get id_token from request failed: %v", err)
	}
	idToken, err := idTokenVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify IDToken with oidc provider failed: %v", err)

	}
	refreshToken, err := o.GetValue(w, r, "refresh_token")
	if err != nil {
		return nil, fmt.Errorf("get refresh_token from request failed: %v", err)
	}
	ts := o.TokenSource(context.Background(), &oauth2.Token{RefreshToken: refreshToken})
	newToken, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("refresh token failed: %v", err)
	}
	return &TokenInfo{
		Token:   newToken,
		IDToken: idToken,
	}, nil
}
func (o *OidcConfig) GetUserInfo(w http.ResponseWriter, r *http.Request) (*UserInfo, error) {
	token, err := o.GetToken(w, r)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, o.OidcProvider)
	if err != nil {
		return nil, fmt.Errorf("initialize provider failed: %v", err)
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	idToken, err := idTokenVerifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verify rawIDToken failed: %v", err)
	}

	var ui UserInfo
	if err = idToken.Claims(&ui); err != nil {
		return nil, fmt.Errorf("parse idToken failed: %v", err)
	}

	return &ui, nil
}

func (o *OidcConfig) GetTokenFromCookie(r *http.Request) (string, error) {
	rawExpiry, err := r.Cookie("expiry")
	if err != nil {
		return "", fmt.Errorf("get expiry from cookie failed: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, rawExpiry.Value)
	if err != nil {
		return "", fmt.Errorf("parse expiry which is from cookie failed: %v", err)
	}
	if expiry.Before(time.Now()) {
		return "", fmt.Errorf("token is expired")
	}

	rawIDToken, err := r.Cookie("id_token")
	if err != nil {
		return "", fmt.Errorf("get id_token from cookie failed: %v", err)
	}

	return rawIDToken.Value, nil
}

func (o *OidcConfig) GetTokenFromRDB(r *http.Request) (string, error) {
	rawExpiry, err := o.GetCookieFromRDB(r, "expiry")
	if err != nil {
		return "", fmt.Errorf("get expiry from cookie failed: %v", err)
	}

	expiry, err := time.Parse(time.RFC3339, rawExpiry.Value)
	if err != nil {
		return "", fmt.Errorf("parse expiry which is from cookie failed: %v", err)
	}
	if expiry.Before(time.Now()) {
		return "", fmt.Errorf("token is expired")
	}

	rawIDToken, err := o.GetCookieFromRDB(r, "id_token")
	if err != nil {
		return "", fmt.Errorf("get id_token from cookie failed: %v", err)
	}

	return rawIDToken.Value, nil
}

func (o *OidcConfig) GetToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := o.GetTokenFromRDB(r)
	if err != nil {
		token, err = o.GetTokenFromCookie(r)
		if err != nil {
			return "", err
		} else {
			o.DelTokenIntoCookie(w, r)
			return "", fmt.Errorf("the token has expired")
		}
	} else {
		o.SyncTokenIntoCookie(w, r, "", o.CookieMaxAge)
	}
	return token, nil
}

func (o *OidcConfig) GetValue(w http.ResponseWriter, r *http.Request, key string) (string, error) {
	value, err := o.GetValueFromRDB(r, key)
	if err != nil {
		value, err = o.GetValueFromCookie(r, key)
		if err != nil {
			return "", err
		} else {
			o.DelTokenIntoCookie(w, r)
			return "", fmt.Errorf("the token has expired")
		}
	} else {
		o.SyncTokenIntoCookie(w, r, "", o.CookieMaxAge)
	}
	return value, nil
}

func (o *OidcConfig) GetValueFromCookie(r *http.Request, key string) (string, error) {
	rawExpiry, err := r.Cookie("expiry")
	if err != nil {
		return "", fmt.Errorf("get expiry from cookie failed: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, rawExpiry.Value)
	if err != nil {
		return "", fmt.Errorf("parse expiry which is from cookie failed: %v", err)
	}
	if expiry.Before(time.Now()) {
		return "", fmt.Errorf("token is expired")
	}

	raw, err := r.Cookie(key)
	if err != nil {
		return "", fmt.Errorf("get %s from cookie failed: %v", key, err)
	}

	return raw.Value, nil
}

func (o *OidcConfig) GetCookieFromRDB(r *http.Request, key string) (http.Cookie, error) {
	fingerprint := httpc.GenerateFingerprint(r)
	var c http.Cookie
	value, err := o.ExecuteRdb(o.RedisCli.RdbHGet, fingerprint, key)
	if err != nil {
		return c, fmt.Errorf("get %s from cookie failed: %v", key, err)
	}
	err = json.Unmarshal([]byte(value), &c)
	return c, err
}

func (o *OidcConfig) GetValueFromRDB(r *http.Request, key string) (string, error) {
	rawExpiry, err := o.GetCookieFromRDB(r, "expiry")
	if err != nil {
		return "", fmt.Errorf("get expiry from cookie failed: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, rawExpiry.Value)
	if err != nil {
		return "", fmt.Errorf("parse expiry which is from cookie failed: %v", err)
	}
	if expiry.Before(time.Now()) {
		return "", fmt.Errorf("token is expired")
	}

	raw, err := o.GetCookieFromRDB(r, key)
	if err != nil {
		return "", fmt.Errorf("get %s from cookie failed: %v", key, err)
	}

	return raw.Value, nil
}

func (o *OidcConfig) TokenFromHeader(header http.Header) (typ string, token string, err error) {
	token = header.Get("Authorization")
	splits := strings.SplitN(token, " ", 2)
	if len(splits) < 2 {
		return "", "", fmt.Errorf("invalid authorization: empty authorization")
	}

	typ = splits[0]
	token = splits[1]
	if typ != "Bearer" && typ != "bearer" {
		return "", "", fmt.Errorf("invalid authorization type: %s", typ)
	}

	return typ, token, nil
}

func StartServer(serverPort uint, oidcConfig OidcConfig) {
	http.HandleFunc("/login", oidcConfig.LoginHandler)
	http.HandleFunc("/callback", oidcConfig.CallbackHandler)
	http.HandleFunc("/user", oidcConfig.UserHandler)
	http.HandleFunc("/logout", oidcConfig.LogoutHandler)
	addr := fmt.Sprintf(":%d", serverPort)
	log.Fatal(http.ListenAndServe(addr, nil))
}
