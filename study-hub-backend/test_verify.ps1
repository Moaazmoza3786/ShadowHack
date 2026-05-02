$body = '{"machine_id": "apollo-01", "flag": "SH{w3lc0m3_t0_th3_m00n}", "user_id": "tester"}'
Invoke-RestMethod -Uri 'http://localhost:5000/verify' -Method Post -Body $body -ContentType 'application/json'
