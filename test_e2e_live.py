import httpx
import sys

BACKEND_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://127.0.0.1:8501"

print(f"Connecting to Backend: {BACKEND_URL}")
print(f"Connecting to Frontend: {FRONTEND_URL}")

with httpx.Client(timeout=15.0) as client:
    # Check Frontend is up
    r_front = client.get(FRONTEND_URL)
    assert r_front.status_code == 200, f"Frontend returned {r_front.status_code}"
    print(f"Frontend is UP: status {r_front.status_code}, contains HTML: {'<!DOCTYPE html>' in r_front.text or '<html' in r_front.text}")

    # Check Backend Health
    r_health = client.get(f"{BACKEND_URL}/api/v1/health")
    assert r_health.status_code == 200, f"Backend health returned {r_health.status_code}"
    print(f"Backend Health: {r_health.json()}")

    # Step A, B, C: Register a fresh test user
    email_a = "testuser@facevox.com"
    pw_a = "Test@12345"
    print(f"\n--- Testing Registration: {email_a} ---")
    r_reg = client.post(f"{BACKEND_URL}/api/v1/auth/register", json={"email": email_a, "password": pw_a})
    if r_reg.status_code == 200:
        reg_json = r_reg.json()
        print(f"Registration SUCCEEDED: user_id={reg_json['user']['id']}, email={reg_json['user']['email']}")
    elif r_reg.status_code == 400 and "already exists" in r_reg.text:
        print(f"User {email_a} already registered from previous run. Testing login directly...")
    else:
        print(f"Registration FAILED: {r_reg.status_code} {r_reg.text}")
        sys.exit(1)

    # Step D & E: Log out and Log back in using testuser@facevox.com
    print(f"\n--- Testing Login with: {email_a} ---")
    r_login = client.post(f"{BACKEND_URL}/api/v1/auth/login", json={"email": email_a, "password": pw_a})
    assert r_login.status_code == 200, f"Login failed: {r_login.status_code} {r_login.text}"
    token_testuser = r_login.json()["access_token"]
    print(f"Login SUCCEEDED: access_token received: {token_testuser[:25]}...")

    # Step F: Confirm demo@facevox.com / Demo@12345
    email_demo = "demo@facevox.com"
    pw_demo = "Demo@12345"
    print(f"\n--- Testing Login with demo account: {email_demo} ---")
    r_demo = client.post(f"{BACKEND_URL}/api/v1/auth/login", json={"email": email_demo, "password": pw_demo})
    assert r_demo.status_code == 200, f"Demo login failed: {r_demo.status_code} {r_demo.text}"
    token_demo = r_demo.json()["access_token"]
    print(f"Demo Login SUCCEEDED: access_token received: {token_demo[:25]}...")

    # Step G: Intentionally incorrect password
    print(f"\n--- Testing Intentionally Incorrect Password for {email_demo} ---")
    r_wrong = client.post(f"{BACKEND_URL}/api/v1/auth/login", json={"email": email_demo, "password": "WrongPassword999"})
    print(f"Incorrect password response: status={r_wrong.status_code}, body={r_wrong.json()}")
    assert r_wrong.status_code == 401, f"Expected 401, got {r_wrong.status_code}"
    assert "Incorrect password" in r_wrong.json().get("detail", ""), "Expected 'Incorrect password' error detail"
    print("Incorrect password handling SUCCEEDED (returned 401 Incorrect password without crashing)!")

    # Step H: Test protected endpoint with token
    print("\n--- Testing Protected Route /api/v1/history ---")
    r_hist = client.get(f"{BACKEND_URL}/api/v1/history", headers={"Authorization": f"Bearer {token_demo}"})
    assert r_hist.status_code == 200, f"Protected route failed: {r_hist.status_code} {r_hist.text}"
    print(f"Protected route SUCCEEDED: history count={len(r_hist.json())}")

    # Step I: Test /api/v1/auth/me
    print("\n--- Testing /api/v1/auth/me ---")
    r_me = client.get(f"{BACKEND_URL}/api/v1/auth/me", headers={"Authorization": f"Bearer {token_testuser}"})
    assert r_me.status_code == 200, f"/auth/me failed: {r_me.status_code}"
    print(f"Auth /me SUCCEEDED: {r_me.json()}")

    # Step J: Test Logout
    print("\n--- Testing /api/v1/auth/logout ---")
    r_logout = client.post(f"{BACKEND_URL}/api/v1/auth/logout")
    assert r_logout.status_code == 200
    print(f"Logout SUCCEEDED: {r_logout.json()}")

print("\n=======================================================")
print("ALL LIVE END-TO-END TESTS PASSED ON BOTH RUNNING PORTS!")
print("=======================================================")
