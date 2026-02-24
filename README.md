# NEXUS - Security Platform Production

Version finale production-ready.

## Quick Start

1. Extract archive
2. cd backend && npm install
3. npm start
4. Deploy (see DEPLOYMENT-GUIDE.md)

## Structure

- backend/ - Node.js API (Render)
- frontend/ - Static site (GitHub Pages)

## Deploy

1. Push to GitHub
2. Render: New Web Service
3. GitHub Pages: Settings → Pages

## Config

Backend: .env with JWT_SECRET
Frontend: config.js with API_URL

## Docs

See DEPLOYMENT-GUIDE.md for full instructions.
