import requests

url = "http://127.0.0.1:8000/predict"

data = {
    "subject": "Security Alert: Unusual Login Attempt Detected on Your Account",
    "email": "We detected a suspicious login attempt. Please verify your account immediately by clicking the link below to avoid temporary suspension: http://account-secure-check.com"
}

res = requests.post(url, json=data)
print(res.json())