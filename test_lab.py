"""Checks that each exploit works on the vulnerable route and is blocked on the secure one."""
import app as lab

lab.init_db()
c = lab.app.test_client()


def login(path, user, pw):
    return c.post(path, data={"username": user, "password": pw}).get_data(as_text=True)


# --- SQL injection ---
payload = "' OR '1'='1' --"
assert "Login successful" in login("/vulnerable/login", payload, "x"), "SQLi should work on vulnerable"
assert "Login successful" not in login("/secure/login", payload, "x"), "SQLi should be blocked on secure"
assert "Login successful" in login("/secure/login", "alice", "alicepass"), "valid login must still work"
assert "Login successful" not in login("/secure/login", "alice", "wrong")
print("SQL injection: exploit works on vulnerable, blocked on secure, normal login OK")

# --- XSS ---
xss = "<script>alert('XSS')</script>"
c.post("/vulnerable/comments", data={"author": "eve", "body": xss})
c.post("/secure/comments", data={"author": "eve", "body": xss})
vuln = c.get("/vulnerable/comments").get_data(as_text=True)
safe_resp = c.get("/secure/comments")
safe = safe_resp.get_data(as_text=True)
assert xss in vuln, "script should be reflected raw on vulnerable"
assert xss not in safe and "&lt;script&gt;" in safe, "script should be escaped on secure"
assert "Content-Security-Policy" in safe_resp.headers
print("XSS: raw script stored on vulnerable, escaped plus CSP on secure")

print("ALL CHECKS PASSED")
