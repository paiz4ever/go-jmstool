package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

func GetClient() *resty.Client {
	return resty.New().
		SetRetryCount(2).
		AddRetryCondition(func(r *resty.Response, err error) bool {
			if err != nil {
				return true
			}
			return r.StatusCode() >= 500
		}).
		SetBaseURL(fmt.Sprintf("https://%s", config.SSH.Host)).
		OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
			path := r.URL
			query := r.QueryParam.Encode()
			if query != "" {
				path += "?" + query
			}
			gmt := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
			headers := map[string]string{
				"accept":    "application/json",
				"X-JMS-ORG": "00000000-0000-0000-0000-000000000002",
				"date":      gmt,
			}
			authHeader := getAuthHeader(
				config.Access.KeyID,
				config.Access.Secret,
				r.Method,
				path,
				headers,
			)
			r.SetHeaders(map[string]string{
				"accept":        headers["accept"],
				"X-JMS-ORG":     headers["X-JMS-ORG"],
				"date":          headers["date"],
				"Authorization": authHeader,
			})
			return nil
		})
}

func generateSignature(secret, stringToSign string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func getAuthHeader(keyID, secret, method, path string, headers map[string]string) string {
	signatureHeaders := []string{"(request-target)", "accept", "date"}
	requestTarget := fmt.Sprintf("%s %s", strings.ToLower(method), path)
	stringToSign := fmt.Sprintf("(request-target): %s\n", requestTarget)
	for _, header := range signatureHeaders[1:] {
		stringToSign += fmt.Sprintf("%s: %s\n", header, headers[header])
	}
	stringToSign = strings.TrimRight(stringToSign, "\n")
	signature := generateSignature(secret, stringToSign)
	authHeader := fmt.Sprintf(
		`Signature keyId="%s",algorithm="hmac-sha256",headers="%s",signature="%s"`,
		keyID,
		strings.Join(signatureHeaders, " "),
		signature,
	)
	return authHeader
}
