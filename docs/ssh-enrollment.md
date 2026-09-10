# Enroll a collector over SSH

Run on the server:

```sh
kite-collector enroll
```

SSH sessions select this flow automatically, including sessions with display
forwarding. Local desktop sessions open the normal browser login. Open the URL printed by the command on your own computer, sign in,
enter the code, and select the organization. Compare the collector and code
with the terminal before approving. Keep the command running until it confirms
that the certificate was saved.

The server makes outbound HTTPS requests. It does not open a login listener,
launch a browser, or require an SSH port forward. Google sign-in and any MFA
verification run in your computer's browser.

Certificates are saved alongside the database by default. The command records
certificate-based local enrollment and starts or restarts the installed service.
`--user` selects the user installation paths. Use `--db` and `--certs-dir` only
when they match the service configuration. A stable machine fingerprint supplies
the collector code; `--agent-code` overrides it. Existing `--token` and
`--enrollment-token` paths remain available.

Device codes and access tokens stay in memory. The local enrollment record
contains a certificate fingerprint, not a reusable API token. Ctrl+C cancels
polling. Denial or expiration requires a new attempt. If issuance fails after
approval, resolve the server error before starting another attempt; device
access tokens are single use.

For private deployments, set `KITE_PKI_ENDPOINT` to the HTTPS PKI base URL.
Deploy the application's `/auth/device` page and matching PKI endpoints first.
`PKI_DEVICE_VERIFICATION_URI` on PKI must point to that page; its origin also
controls browser access. The app's `VITE_PKI_URL` and Content Security Policy
must allow the same PKI endpoint.

The protocol follows [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html),
including polling intervals, `slow_down`, denial, and expiration responses.
