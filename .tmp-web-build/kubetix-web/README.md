# KubeTix Web UI

The web dashboard for KubeTix - Temporary Kubernetes Access Manager.

## Features

- 🎯 View all active grants
- 📋 Create new time-limited access grants
- 🔴 Revoke access instantly
- 📊 Dashboard with statistics
- 🎨 Clean, modern UI

## Tech Stack

- **Framework**: Next.js 14
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Language**: TypeScript
- **Date Handling**: date-fns

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Environment Variables

- `API_URL` - Backend API endpoint (default: `http://localhost:8000`)

## API Integration

The web UI expects the following API endpoints:

### GET `/grants`
Returns list of active grants

### POST `/grants`
Create a new grant
```json
{
  "cluster_name": "prod",
  "namespace": "production",
  "role": "edit",
  "expiry_hours": 4
}
```

### DELETE `/grants/:id`
Revoke a grant

## Deployment

### Vercel (Recommended)

```bash
vercel deploy
```

### Docker

```bash
docker build -t kubetix-web .
docker run -p 3000:3000 kubetix-web
```

## Screenshots

See the live demo at: [URL when deployed]
