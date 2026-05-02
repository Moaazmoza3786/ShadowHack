$body = '{"model":"qwen2.5-coder:7b","prompt":"Hello from tests","temperature":0.5,"max_tokens":128}'
Invoke-RestMethod -Uri 'http://localhost:5000/api/ai/query' -Method Post -Body $body -ContentType 'application/json'
