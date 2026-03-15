/*
	GuA-SoundCloud-sdk-go is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	GuA-SoundCloud-sdk-go is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with GuA-SoundCloud-sdk-go.  If not, see <http://www.gnu.org/licenses/>

	Copyright (c) 2026 Gleb Obitotsky
*/

package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ImperGram/GuA-SoundCloud-SDK-Go/auth/models"
	"hub.mos.ru/gua/crypto-lib/src/pkce"
)

type AuthSoundCloud struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	HTTPClient   *http.Client
}

func NewAuth(clientID, clientSecret, redirectURI string) *AuthSoundCloud {
	return &AuthSoundCloud{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		HTTPClient:   &http.Client{},
	}
}

type AuthData struct {
	URL          string
	State        string
	CodeVerifier string
}

func (a *AuthSoundCloud) GetAuthURL() (*AuthData, error) {
	state, err := pkce.RString(32)
	if err != nil {
		return nil, err
	}
	codeVerifier, err := pkce.RString(64)
	if err != nil {
		return nil, err
	}
	codeChallenge := pkce.CodeChallenge(codeVerifier)

	params := url.Values{}
	params.Add("client_id", a.ClientID)
	params.Add("redirect_uri", a.RedirectURI)
	params.Add("response_type", "code")
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("state", state)

	fullURL := "https://secure.soundcloud.com/authorize?" + params.Encode()

	return &AuthData{
		URL:          fullURL,
		State:        state,
		CodeVerifier: codeVerifier,
	}, nil
}

func (a *AuthSoundCloud) ExchangeCodeForToken(code, codeVerifier string) (*models.TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", a.ClientSecret)
	data.Set("redirect_uri", a.RedirectURI)
	data.Set("code", code)
	data.Set("code_verifier", codeVerifier)

	return a.doTokenRequest(data)
}

func (a *AuthSoundCloud) RefreshToken(refreshToken string) (*models.TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", a.ClientID)
	data.Set("client_secret", a.ClientSecret)
	data.Set("refresh_token", refreshToken)

	return a.doTokenRequest(data)
}

func (a *AuthSoundCloud) SignOut(accessToken string) (bool, error) {
	jsonBody := []byte(fmt.Sprintf(`{"access_token": "%s"}`, accessToken))

	req, err := http.NewRequest("POST", "https://secure.soundcloud.com/sign-out", bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		return true, nil
	}

	return false, fmt.Errorf("sign-out error: status %d", resp.StatusCode)
}

func (a *AuthSoundCloud) doTokenRequest(data url.Values) (*models.TokenResponse, error) {
	req, err := http.NewRequest("POST", "https://secure.soundcloud.com/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed: status %d", resp.StatusCode)
	}

	var token models.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}
