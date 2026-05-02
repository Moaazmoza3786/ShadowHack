$body = '{"machine_id": "apollo-01", "flag": "WRONG-FLAG", "user_id": "tester"}'
Invoke-RestMethod -Uri 'http://localhost:5000/verify' -Method Post -Body $body -ContentType 'application/json'
