# Break It, Fix It

> **Warning: intentionally vulnerable code.** This is an educational lab for a class project. Run it only on your own computer (it binds to 127.0.0.1). Never deploy it, expose it to a network, or reuse its code in a real application. Practice these techniques only on systems you own or have written permission to test.

Project 02 of a cybersecurity course: a vulnerable website investigation.

Research question: How can a web application weakness change what a user can see or do?

A small, intentionally vulnerable site for a class project. Run it only on your own machine.
It listens on 127.0.0.1 only. Never deploy it or expose it to a network.

## 1. Setup

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Use "Reset database" on the home page to start clean.
Run `python test_lab.py` to confirm every exploit works on the vulnerable page and is blocked on the secure one.

## 2. Burp Suite setup

1. Open Burp Suite Community, go to Proxy, then Intercept, then "Open browser" (the built-in browser already trusts Burp).
2. Browse to http://127.0.0.1:5000.
3. Keep Intercept off while browsing, switch it on only when you want to edit a request.
4. Use Proxy > HTTP history to see every request and response for your report.

## 3. Topic 1: SQL injection (login)

Expected behavior: wrong username or password means "Invalid username or password."

Vulnerable page: /vulnerable/login

1. Submit `alice` / `wrongpass`. Capture the POST in Burp. Result: login fails.
2. Submit username `' OR '1'='1' --` with any password. Result: login succeeds (as the first user, admin).
3. Submit username `'` alone. Result: a database error leaks the query structure.
4. Screenshot the "Query run" line, which shows how the input changed the SQL.

Why it works: the server builds `... WHERE username = '<input>' AND password = '<input>'`.
The `--` comments out the password check and `OR '1'='1'` is always true.

Fix: /secure/login uses a parameterized query (`WHERE username = ? AND password = ?`) and a generic error message.
Repeat the same payloads. Result: login fails, no error details.

Honest note for your report: this lab stores plain-text passwords to keep the demo simple. In a real app,
passwords should be hashed (bcrypt or argon2), which is a good "further hardening" point.

## 4. Topic 2: Cross-site scripting (comments)

Expected behavior: a comment shows up as plain text.

Vulnerable page: /vulnerable/comments

1. Post name `eve`, comment `hello`. Result: shows as text.
2. Post comment `<b>bold test</b>`. Result: renders bold, proving HTML is not escaped.
3. Post comment `<script>alert('XSS')</script>`. Result: an alert pops up for every visitor who loads the page (stored XSS).
4. Capture the POST in Burp to show the payload in the request, and the response to show it returned unescaped.

Why it works: stored comment text is inserted into the HTML without encoding, so the browser runs it as code.
Real impact: an attacker script could change what the page shows or act as the visitor.

Fix: /secure/comments HTML-escapes output (`<` becomes `&lt;`) and sends a Content-Security-Policy header.
Post the same payloads. Result: they appear as harmless text and nothing executes.

## 5. Expected vs actual table (for your report)

| Test | Input | Expected | Vulnerable result | Secure result |
|------|-------|----------|-------------------|---------------|
| SQLi 1 | alice / wrongpass | Rejected | Rejected | Rejected |
| SQLi 2 | `' OR '1'='1' --` | Rejected | Logged in (bypass) | Rejected |
| SQLi 3 | `'` | Generic error | DB error leaked | Generic message |
| XSS 1 | `<b>bold</b>` | Plain text | Rendered as HTML | Plain text |
| XSS 2 | `<script>alert('XSS')</script>` | Plain text | Script runs | Plain text |

## 6. Final demo outline (about 5 minutes)

1. Research question and the app in one sentence (30s).
2. Vulnerable login: normal login fails, injection succeeds, show the query line and the Burp request (90s).
3. Fix: parameterized query, same payload fails (45s).
4. Vulnerable comments: inject script, alert fires (60s).
5. Fix: escaping plus CSP, same payload shows as text (45s).
6. Takeaway: never trust input, separate data from code, encode output (30s).

## 7. Code map

- `app.py`: the whole site. Search for `VULNERABLE` and `FIX` comments to find each before and after.
- `test_lab.py`: automated proof that exploits work and fixes hold.
