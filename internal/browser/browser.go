// Package browser serves only the reviewed embedded client artifacts. It has no
// payload, credentials, database, filesystem-path or execution capability.
package browser

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

const Policy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'none'"

var publicAssets = map[string]struct{ name, contentType string }{
	"/":                                {"index.html", "text/html; charset=utf-8"},
	"/assets/app.js":                   {"app.js", "text/javascript; charset=utf-8"},
	"/assets/app.css":                  {"app.css", "text/css; charset=utf-8"},
	"/assets/hash-worker.js":           {"hash-worker.js", "text/javascript; charset=utf-8"},
	"/assets/app.js.LEGAL.txt":         {"app.js.LEGAL.txt", "text/plain; charset=utf-8"},
	"/assets/hash-worker.js.LEGAL.txt": {"hash-worker.js.LEGAL.txt", "text/plain; charset=utf-8"},
	"/assets/third-party-notices.txt":  {"third-party-notices.txt", "text/plain; charset=utf-8"},
}

var downloadErrorPage = template.Must(template.New("download-refused").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Download unavailable · freightctl</title><link rel="stylesheet" href="/assets/app.css"></head><body><main class="welcome"><section class="login-card"><h1>Download unavailable</h1><p>The server could not authorize or verify this file. It may be held, its access may have changed, or a dependency may be unavailable. No file was provided.</p><p class="help">Server result: <code>{{.}}</code></p><a href="/">Return to your workspace</a></section></main></body></html>`))

func DownloadError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Security-Policy", Policy)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = downloadErrorPage.Execute(w, code)
}

func Serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", Policy)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", 405)
		return
	}
	asset, ok := publicAssets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/" + asset.name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", asset.contentType)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}
