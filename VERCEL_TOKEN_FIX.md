# Vercel Token Error - Solution Guide

## Problem
```
Error: The specified token is not valid. Use `vercel login` to generate a new token.
```

This error occurs when:
- Your Vercel authentication token has expired
- The token stored locally is invalid
- You're not authenticated with Vercel CLI
- The VERCEL_TOKEN environment variable is invalid

---

## Solution Options

### Option 1: Re-authenticate with Vercel (Recommended)

```bash
# Step 1: Clear existing authentication
vercel logout

# Step 2: Log in to Vercel
vercel login

# Step 3: Follow the prompts:
#   - Select authentication method (email or SAML)
#   - Verify your identity
#   - Token will be stored automatically
```

After login, your local `.vercel/auth.json` will contain a valid token.

---

### Option 2: Generate New Token via Vercel Dashboard

1. Go to https://vercel.com/account/tokens
2. Click "Create Token"
3. Set token name (e.g., "Local Development")
4. Set expiration (recommended: 90 days or longer)
5. Copy the token
6. Set environment variable:

```bash
# Windows PowerShell
$env:VERCEL_TOKEN = "your-token-here"

# Windows CMD
set VERCEL_TOKEN=your-token-here

# Linux/Mac
export VERCEL_TOKEN="your-token-here"
```

---

### Option 3: Configure for GitHub Actions

If you're deploying via GitHub Actions, add the token as a secret:

```yaml
name: Deploy to Vercel

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vercel/action@v28
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
```

---

## Vercel Configuration (Current Setup)

### vercel.json (Already Configured)
```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "installCommand": "npm install",
  "framework": "vite",
  "rootDirectory": "study-hub-react",
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```

✅ This configuration is correct and ready for deployment.

---

## Deployment Steps

### After Authentication:

```bash
# Option A: Deploy the current project
vercel

# Option B: Deploy to production
vercel --prod

# Option C: Deploy specific directory
vercel --cwd ./study-hub-react
```

---

## Troubleshooting

### Check Authentication Status
```bash
vercel whoami
```
Should return your Vercel account email.

### View Stored Token Location
- **Windows:** `%USERPROFILE%\.vercel\auth.json`
- **Linux/Mac:** `~/.vercel/auth.json`

### Reset Authentication
```bash
# Remove stored credentials
rm ~/.vercel/auth.json          # Linux/Mac
del %USERPROFILE%\.vercel\auth.json  # Windows

# Re-authenticate
vercel login
```

---

## Environment Variables for CI/CD

If deploying from CI/CD pipeline, ensure these are set:

| Variable | Required | Purpose |
|----------|----------|---------|
| `VERCEL_TOKEN` | ✅ Yes | Authentication token |
| `VERCEL_PROJECT_ID` | ✅ Yes | Project identifier |
| `VERCEL_ORG_ID` | ✅ Yes | Organization identifier |

### Find Your IDs

```bash
# After authentication, run:
vercel project list
vercel teams list
```

Or visit:
- Project ID: https://vercel.com/dashboard → Project → Settings → Project ID
- Org ID: https://vercel.com/account/team/settings (if using teams)

---

## ShadowHack Vercel Setup

### Project Details
- **Framework:** Vite (React)
- **Build Command:** `npm run build`
- **Install Command:** `npm install`
- **Output Directory:** `dist`
- **Root Directory:** `study-hub-react`
- **Environment:** Production ready

### Deploy Command
```bash
cd C:\Users\mmoza\Desktop\Study-hub3
vercel --prod
```

---

## Next Steps

1. **Authenticate:**
   ```bash
   vercel logout
   vercel login
   ```

2. **Verify Setup:**
   ```bash
   vercel whoami
   ```

3. **Deploy:**
   ```bash
   vercel --prod
   ```

4. **Check Deployment:**
   - Visit https://vercel.com/dashboard
   - Your ShadowHack project should show deployment status
   - Click deployment to view logs

---

## Success Indicators

✅ `vercel whoami` returns your email  
✅ `vercel deploy` runs without token errors  
✅ Build completes successfully  
✅ Application accessible at `https://shadowhack-*.vercel.app`  

---

## Support

For more help:
- Vercel Docs: https://vercel.com/docs
- Vercel CLI: https://vercel.com/cli
- GitHub Issues: https://github.com/vercel/vercel/issues
