import sys
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.user_db import get_user_by_email, normalize_email

client = TestClient(app)

print("=== Starting Comprehensive Authentication Test Suite ===")

# 1. Test registration of a fresh test user
reg_email = "testuser@facevox.com"
reg_pw = "Test@12345"

print(f"\n1. Testing Registration: {reg_email}")
reg_resp = client.post("/api/v1/auth/register", json={"email": reg_email, "password": reg_pw})
if reg_resp.status_code == 400 and "already exists" in reg_resp.text:
    print("User already existed, proceeding...")
else:
    print(f"Register status: {reg_resp.status_code}")
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert "access_token" in reg_data, "Token missing in registration"
    assert reg_data["user"]["email"] == reg_email.lower(), "Email not normalized"
    print("Registration SUCCESS!")

# 2. Verify user in database
db_user = get_user_by_email(reg_email)
assert db_user is not None, "User not found in DB"
print(f"User in DB: {db_user['email']} with ID: {db_user['id']}")

# 3. Test duplicate registration (should fail with 400)
print("\n2. Testing Duplicate Registration Rejection")
dup_resp = client.post("/api/v1/auth/register", json={"email": reg_email.upper(), "password": reg_pw})
print(f"Duplicate status: {dup_resp.status_code}, detail: {dup_resp.json().get('detail')}")
assert dup_resp.status_code == 400, "Duplicate registration should fail"
print("Duplicate rejection PASS!")

# 4. Test Login with newly registered user
print(f"\n3. Testing Login for newly registered user: {reg_email}")
login_resp = client.post("/api/v1/auth/login", json={"email": reg_email, "password": reg_pw})
print(f"Login status: {login_resp.status_code}")
assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
login_data = login_resp.json()
testuser_token = login_data["access_token"]
print("Login SUCCESS!")

# 5. Test Case-insensitivity and Whitespace Normalization
print(f"\n4. Testing Email Normalization (mixed case + whitespace: '  TestUser@FaceVox.com  ')")
norm_resp = client.post("/api/v1/auth/login", json={"email": f"  {reg_email.upper()}  ", "password": reg_pw})
assert norm_resp.status_code == 200, f"Email normalization login failed: {norm_resp.text}"
print("Email normalization PASS!")

# 6. Test Login with intentionally WRONG password
print("\n5. Testing Intentionally Incorrect Password")
wrong_resp = client.post("/api/v1/auth/login", json={"email": reg_email, "password": "WrongPassword!999"})
print(f"Wrong password status: {wrong_resp.status_code}, response: {wrong_resp.text}")
assert wrong_resp.status_code == 401, "Wrong password should return 401"
assert "Incorrect password" in wrong_resp.text or "Invalid" in wrong_resp.text
print("Incorrect password handling PASS!")

# 7. Test Login with Demo Account (TASK 5)
demo_email = "demo@facevox.com"
demo_pw = "Demo@12345"
print(f"\n6. Testing Demo Account Login: {demo_email}")
demo_resp = client.post("/api/v1/auth/login", json={"email": demo_email, "password": demo_pw})
print(f"Demo login status: {demo_resp.status_code}")
assert demo_resp.status_code == 200, f"Demo account login failed: {demo_resp.text}"
demo_token = demo_resp.json()["access_token"]
print("Demo account login PASS!")

# 8. Test Protected Route: /api/v1/auth/me
print("\n7. Testing Protected Route /api/v1/auth/me")
me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {testuser_token}"})
print(f"/me status: {me_resp.status_code}, data: {me_resp.json()}")
assert me_resp.status_code == 200, f"/me failed: {me_resp.text}"
assert me_resp.json()["email"] == reg_email.lower()
print("Protected route /api/v1/auth/me PASS!")

# 9. Test Protected Route without token (should fail 401)
print("\n8. Testing Protected Route Without Token")
unauth_resp = client.get("/api/v1/auth/me")
assert unauth_resp.status_code == 401, "Protected route without token should return 401"
print("Unauthorized access rejection PASS!")

# 10. Test Protected Route: /api/v1/history
print("\n9. Testing Protected History Route: /api/v1/history")
hist_resp = client.get("/api/v1/history", headers={"Authorization": f"Bearer {demo_token}"})
print(f"/history status: {hist_resp.status_code}")
assert hist_resp.status_code == 200, f"/history failed: {hist_resp.text}"
print("Protected history access PASS!")

# 11. Test Logout Route
print("\n10. Testing Logout Route: /api/v1/auth/logout")
logout_resp = client.post("/api/v1/auth/logout")
assert logout_resp.status_code == 200
print("Logout PASS!")

print("\n=== ALL AUTHENTICATION TESTS PASSED SUCCESSFULLY! ===")
