package dashboard

import (
	"fmt"
	"html/template"
	"net/http"
)

type kiteLoginView struct {
	CollectorURL string
}

type kiteSuccessView struct {
	DashboardURL string
}

const kiteLoginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Link Kite Collector - Vulnertrack</title>
<link rel="stylesheet" href="/static/style.css">
<style>
  body.kite-auth-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: radial-gradient(circle at 50% 50%, #fdfdfd 0%, #f4f5f7 100%);
    color: #1C252E;
  }
  .kite-auth-card {
    background: #ffffff;
    border: 1px solid rgba(145, 158, 171, 0.16);
    border-radius: 16px;
    box-shadow: 0 12px 40px -4px rgba(145, 158, 171, 0.12), 0 2px 10px -2px rgba(145, 158, 171, 0.08);
    width: 100%;
    max-width: 420px;
    padding: 40px 32px;
    box-sizing: border-box;
    text-align: center;
  }
  .kite-auth-logo-container {
    display: flex;
    justify-content: center;
    margin-bottom: 24px;
  }
  .kite-auth-logo {
    width: 64px;
    height: 64px;
    object-fit: contain;
  }
  .kite-auth-title {
    font-size: 1.5rem;
    font-weight: 800;
    margin: 0 0 12px 0;
    color: #1C252E;
    letter-spacing: -0.5px;
  }
  .kite-auth-desc {
    font-size: 0.925rem;
    line-height: 1.5;
    color: #637381;
    margin: 0 0 32px 0;
  }
  .kite-auth-btn-stack {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-bottom: 28px;
  }
  .kite-auth-btn-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 48px;
    border-radius: 24px;
    background: #FF3131;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 4px 12px rgba(255, 49, 49, 0.2);
  }
  .kite-auth-btn-primary:hover {
    background: #e02828;
    transform: translateY(-1px);
    box-shadow: 0 6px 16px rgba(255, 49, 49, 0.3);
  }
  .kite-auth-btn-secondary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 48px;
    border-radius: 24px;
    background: transparent;
    border: 1px solid rgba(145, 158, 171, 0.32);
    color: #1C252E;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
  }
  .kite-auth-btn-secondary:hover {
    background: rgba(145, 158, 171, 0.08);
    border-color: #1C252E;
  }
  .kite-auth-divider {
    height: 1px;
    background: rgba(145, 158, 171, 0.12);
    margin: 0 0 24px 0;
  }
  .kite-auth-status-container {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .kite-auth-status-dot {
    width: 8px;
    height: 8px;
    background-color: #22C55E;
    border-radius: 50%;
    position: relative;
  }
  .kite-auth-status-dot::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: #22C55E;
    border-radius: 50%;
    animation: pulse 1.8s infinite ease-in-out;
  }
  @keyframes pulse {
    0% { transform: scale(1); opacity: 0.8; }
    100% { transform: scale(2.6); opacity: 0; }
  }
  .kite-auth-status-text {
    font-size: 0.8rem;
    font-weight: 600;
    color: #22C55E;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .kite-auth-panel-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    height: 40px;
    padding: 0 20px;
    border-radius: 20px;
    background: transparent;
    border: 1px solid rgba(145, 158, 171, 0.32);
    color: #637381;
    font-size: 0.85rem;
    font-weight: 500;
    text-decoration: none;
    transition: all 0.2s ease-in-out;
    cursor: pointer;
    margin-top: 4px;
  }
  .kite-auth-panel-btn:hover {
    background: rgba(145, 158, 171, 0.08);
    border-color: #1C252E;
    color: #1C252E;
  }
  .kite-auth-panel-btn code {
    font-family: monospace;
    background: #f4f6f8;
    padding: 2px 8px;
    border-radius: 4px;
    color: #1C252E;
    font-weight: 600;
    font-size: 0.82rem;
  }
  .kite-auth-panel-btn:hover code {
    background: rgba(145, 158, 171, 0.16);
  }
</style>
</head>
<body class="kite-auth-page">
<div class="kite-auth-card">
  <div class="kite-auth-logo-container">
    <img class="kite-auth-logo" src="/static/img/logo.png" alt="Vulnertrack Logo">
  </div>
  <h1 class="kite-auth-title">Link Kite Collector</h1>
  <p class="kite-auth-desc">Connect this collector to your account to view assets, software, and findings in your dashboard.</p>
  
  <div class="kite-auth-btn-stack">
    <a class="kite-auth-btn-primary" href="https://app.vulnertrack.com/kite/signin/oauth?collector={{.CollectorURL}}">Sign In</a>
  </div>

  <div class="kite-auth-divider"></div>

  <div class="kite-auth-status-container">
    <div class="kite-auth-status-dot"></div>
    <span class="kite-auth-status-text">Collector installed</span>
  </div>
  {{if .CollectorURL}}
  <a class="kite-auth-panel-btn" href="{{.CollectorURL}}">
    Open local panel: <code>{{.CollectorURL}}</code>
  </a>
  {{end}}
</div>
</body>
</html>`

var kiteLoginTmpl = template.Must(template.New("kiteLogin").Parse(kiteLoginTemplate))

const kiteSuccessTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Granted - Kite Collector</title>
<link rel="stylesheet" href="/static/style.css">
<style>
  body.kite-success-page {
    min-height: 100vh;
    margin: 0;
    background: #ffffff;
    color: #1C252E;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  .kite-success-wrap {
    width: min(420px, calc(100vw - 48px));
    margin: 0 auto;
    padding-top: 22vh;
  }
  .kite-success-logo {
    display: block;
    width: 148px;
    height: auto;
    margin-bottom: 48px;
  }
  .kite-success-heading {
    display: flex;
    align-items: center;
    gap: 14px;
    margin: 0 0 18px 0;
    font-size: 1.75rem;
    font-weight: 600;
    letter-spacing: 0;
    color: #1C252E;
  }
  .kite-success-check {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    background: #22C55E;
    color: #ffffff;
    font-size: 1.2rem;
    font-weight: 800;
    line-height: 1;
    box-shadow: 0 5px 14px rgba(34, 197, 94, 0.28);
  }
  .kite-success-copy {
    margin: 0 0 12px 0;
    color: #637381;
    font-size: 1rem;
    line-height: 1.45;
  }
  .kite-success-actions {
    margin-top: 32px;
  }
  .kite-success-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    padding: 0 20px;
    border-radius: 22px;
    background: #FF3131;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
    text-decoration: none;
    box-shadow: 0 4px 12px rgba(255, 49, 49, 0.2);
    transition: background 0.2s ease-in-out, box-shadow 0.2s ease-in-out, transform 0.2s ease-in-out;
  }
  .kite-success-btn:hover {
    background: #e02828;
    box-shadow: 0 6px 16px rgba(255, 49, 49, 0.3);
    transform: translateY(-1px);
  }
  @media (max-width: 640px) {
    .kite-success-wrap {
      padding-top: 18vh;
    }
    .kite-success-logo {
      width: 128px;
      margin-bottom: 36px;
    }
    .kite-success-heading {
      font-size: 1.45rem;
    }
  }
</style>
</head>
<body class="kite-success-page">
<main class="kite-success-wrap" aria-labelledby="kite-success-title">
  <img class="kite-success-logo" src="/static/img/vulnertrack_banner_dark.png" alt="Vulnertrack">
  <h1 class="kite-success-heading" id="kite-success-title">
    <span>Success!</span>
    <span class="kite-success-check" aria-hidden="true">✓</span>
  </h1>
  <p class="kite-success-copy">You've granted Kite Collector access to your Vulnertrack account.</p>
  <p class="kite-success-copy">To continue, return to the dashboard and finish reviewing your collector status.</p>
  <div class="kite-success-actions">
    <a class="kite-success-btn" href="{{.DashboardURL}}">Go to Dashboard</a>
  </div>
</main>
</body>
</html>`

var kiteSuccessTmpl = template.Must(template.New("kiteSuccess").Parse(kiteSuccessTemplate))

func serveKiteLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	collectorURL := r.URL.Query().Get("collector")
	if collectorURL == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		collectorURL = scheme + "://" + r.Host
	}
	view := kiteLoginView{
		CollectorURL: collectorURL,
	}
	if err := kiteLoginTmpl.Execute(w, view); err != nil {
		http.Error(w, fmt.Sprintf("render kite login: %v", err), http.StatusInternalServerError)
	}
}

func serveKiteSuccessPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardURL := r.URL.Query().Get("dashboard")
	if dashboardURL == "" {
		dashboardURL = "/assets"
	}
	view := kiteSuccessView{
		DashboardURL: dashboardURL,
	}
	if err := kiteSuccessTmpl.Execute(w, view); err != nil {
		http.Error(w, fmt.Sprintf("render kite success: %v", err), http.StatusInternalServerError)
	}
}
