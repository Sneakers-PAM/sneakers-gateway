// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package share

import (
	"html/template"
	"net/http"
)

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Shared secret</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1b1b1b}
pre{background:#f3f3f3;padding:1rem;border-radius:6px;white-space:pre-wrap;word-break:break-all}
button{font:inherit;padding:.6rem 1.2rem}</style></head><body>
<h1>Shared secret</h1>
{{if .Value}}<p>This is shown once. Copy it now; the link won't work again.</p><pre>{{.Value}}</pre>
{{else if .Ready}}<p>Someone shared a secret with you. It can be opened once. Open it only when you're ready to copy it.</p>
<form method="post"><button type="submit">Show the secret</button></form>
{{else}}<p>{{.Message}}</p>{{end}}
</body></html>
`))

type pageData struct {
	Value, Message string
	Ready          bool
}

// page writes the answer for an outcome. Everything but the value is plain
// text that says nothing about the secret.
func (s *Service) page(w http.ResponseWriter, r *http.Request, out outcome, value string) {
	d := pageData{}
	code := http.StatusOK
	switch out {
	case outcomeOK:
		d.Value, d.Ready = value, value == ""
	case outcomeNotFound:
		code, d.Message = http.StatusNotFound, "This link isn't available."
	case outcomeGone:
		code, d.Message = http.StatusGone, "This link has already been used, has expired, or was withdrawn."
	case outcomePending:
		code, d.Message = http.StatusConflict, "The owner of this secret hasn't approved sharing it yet. Try this link again later; it hasn't been used up."
	default:
		code, d.Message = http.StatusServiceUnavailable, "This link can't be opened right now. Try again in a moment; it hasn't been used up."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_ = pageTmpl.Execute(w, d)
}
