# Enroll a collector over SSH

Run on the server:

```sh
kite-collector enroll
```

SSH sessions automatically use the remote device flow, including sessions with
display forwarding. Open the complete URL printed in the terminal on your own
computer. It includes a short-lived encrypted authorization ticket, so the page
preserves the transaction through sign-in and authorizes without displaying or
asking you to type a code. If the account has several organizations and no
active organization, select one. Keep the command running until it confirms
that the certificate was saved. `--no-browser` also forces this flow.

With option 2, the server makes outbound HTTPS requests. It does not open a
login listener, launch a browser, or require an SSH port forward. Google sign-in
and any MFA verification run in your computer's browser.

Certificates are saved alongside the database by default. The command records
certificate-based local enrollment and starts or restarts the installed service.
`--user` selects the user installation paths. Use `--db` and `--certs-dir` only
when they match the service configuration. A stable machine fingerprint supplies
the collector code; `--agent-code` overrides it. Existing `--token` and
`--enrollment-token` paths remain available.

Device codes and access tokens stay in memory. Authorization expires after five
minutes and each transaction can be consumed only once. The local enrollment record
contains a certificate fingerprint, not a reusable API token. Ctrl+C cancels
polling. Denial or expiration requires a new attempt. If issuance fails after
approval, resolve the server error before starting another attempt; device
access tokens are single use.

For private deployments, set `KITE_PKI_ENDPOINT` to the HTTPS PKI base URL.
Deploy the application's `/auth/device` page and matching PKI endpoints first.
`PKI_DEVICE_VERIFICATION_URI` on PKI must point to that page. Browser approval
travels through the authenticated `device-authorization` Edge Function.

The protocol follows [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html),
including polling intervals, `slow_down`, denial, and expiration responses.
