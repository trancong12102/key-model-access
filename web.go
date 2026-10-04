package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

//go:embed web/settings.html web/settings.css web/settings.js web/theme.js
var webAssets embed.FS

func settingsPage() ([]byte, error) {
	template, err := webAssets.ReadFile("web/settings.html")
	if err != nil {
		return nil, fmt.Errorf("read settings template: %w", err)
	}
	styles, err := webAssets.ReadFile("web/settings.css")
	if err != nil {
		return nil, fmt.Errorf("read settings styles: %w", err)
	}
	script, err := webAssets.ReadFile("web/settings.js")
	if err != nil {
		return nil, fmt.Errorf("read settings script: %w", err)
	}
	themeScript, err := webAssets.ReadFile("web/theme.js")
	if err != nil {
		return nil, fmt.Errorf("read theme script: %w", err)
	}
	nonce, err := contentNonce()
	if err != nil {
		return nil, err
	}

	body := strings.NewReplacer(
		"{{NONCE}}", nonce,
		"{{CSS}}", string(styles),
		"{{JS}}", string(script),
		"{{THEME_JS}}", string(themeScript),
	).Replace(string(template))
	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"style-src 'nonce-" + nonce + "'",
		"connect-src 'self'",
		"img-src data:",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'self'",
	}, "; ")

	return okEnvelope(managementResponse{
		StatusCode: http.StatusOK,
		Headers: http.Header{
			"Content-Type":               []string{"text/html; charset=utf-8"},
			"Cache-Control":              []string{"no-store"},
			"Content-Security-Policy":    []string{csp},
			"Referrer-Policy":            []string{"no-referrer"},
			"X-Content-Type-Options":     []string{"nosniff"},
			"X-Frame-Options":            []string{"SAMEORIGIN"},
			"Permissions-Policy":         []string{"camera=(), geolocation=(), microphone=(), payment=(), usb=()"},
			"Cross-Origin-Opener-Policy": []string{"same-origin"},
		},
		Body: []byte(body),
	})
}

func contentNonce() (string, error) {
	buffer := make([]byte, 18)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate content nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
