# IP Logger

Een professionele IP tracking applicatie met Node.js en SQLite.

## Installatie

1. Installeer Node.js: https://nodejs.org/en/download
2. Clone deze repository
3. Kopieer `.env.example` naar `.env` en pas de waarden aan:
   ```
   cp .env.example .env
   ```
4. Genereer een gehasht wachtwoord voor je admin account:
   ```
   npm run hash-password
   ```
   Voer je wachtwoord in en kopieer de gegenereerde hash naar je `.env` bestand als `ADMIN_PASS_HASH`.
5. Installeer dependencies:
   ```
   npm install
   ```
6. Start de server:
   ```
   npm start
   ```
   De SQLite database wordt automatisch aangemaakt in `database.sqlite`.

## Deploy

Voor productie deploy wordt aanbevolen om PostgreSQL te gebruiken. SQLite is prima voor development en kleine deployments.

Voor PostgreSQL deploy:
1. Push code naar GitHub
2. Maak een PostgreSQL database aan (bijv. Render, Railway, Supabase)
3. Voeg environment variables toe:
   - `ADMIN_USER`: Je gebruikersnaam
   - `ADMIN_PASS_HASH`: Gehasht wachtwoord (genereer met `npm run hash-password`)
   - `DATABASE_URL`: PostgreSQL connection string
   - `SESSION_SECRET`: Een willekeurige string voor sessie encryptie (minimaal 32 karakters)
   - `ALLOWED_ORIGINS`: Comma-gescheiden lijst van toegestane origins

## Gebruik

1. Ga naar `http://localhost:3000/admin`
2. Log in met de credentials uit je `.env` bestand
3. Maak tracking links aan met een naam en doel URL
4. Deel de tracking link en bekijk de logs in het dashboard

## Features

- 🎯 Maak tracking links aan met custom bestemmingen
- 📊 Bekijk IP adres, locatie, browser en OS van bezoekers
- 🗺️ Geolocatie met kaartweergave
- 🔐 Session-based authenticatie met bcrypt password hashing
- 🛡️ Verbeterde security: HSTS, CSRF protection, strict CORS
- ⚡ Rate limiting op alle API endpoints
- 💾 SQLite database (geen externe database server nodig)
- 🚀 Query caching voor betere performance
- 📈 Health check endpoint
- 🚀 Graceful shutdown
- 📝 Request logging en tracking
- 🌐 CORS support
- 💾 Gzip compression
- ✅ Input validation met Joi
- 🎨 Moderne UI met dark theme

## Environment Variables

- `PORT`: Server poort (default: 3000)
- `ADMIN_USER`: Gebruikersnaam voor dashboard
- `ADMIN_PASS`: Wachtwoord voor dashboard (legacy, plain text)
- `ADMIN_PASS_HASH`: Gehasht wachtwoord (aanbevolen voor productie)
- `DB_PATH`: Pad naar SQLite database (default: ./database.sqlite)
- `DATABASE_URL`: PostgreSQL connection string (optioneel, override SQLite)
- `SESSION_SECRET`: Secret voor sessie encryptie (verplicht in productie)
- `ALLOWED_ORIGINS`: CORS toegestane origins (strict in productie)
- `NODE_ENV`: Environment (development/production)

## API Endpoints

- `GET /` - Homepagina
- `GET /health` - Health check
- `GET /login` - Login pagina
- `POST /api/login` - Login endpoint
- `POST /api/logout` - Logout endpoint
- `GET /admin` - Admin dashboard (vereist authenticatie)
- `GET /api/trackers` - Lijst van trackers (vereist authenticatie)
- `POST /api/save-tracker` - Maak of update tracker (vereist authenticatie)
- `POST /api/delete-tracker` - Verwijder tracker (vereist authenticatie)
- `GET /api/logs?limit=500&offset=0` - Lijst van logs met paginering (vereist authenticatie)
- `GET /api/summary` - Statistieken (vereist authenticatie)
- `POST /api/log-geo` - Client-side geo logging
- `GET /:trackerId` - Tracker redirect
- `GET /track/:id` - Tracker redirect
- `GET /pixel/:trackerId.png` - Tracking pixel

## Beveiliging

- Rate limiting op alle API endpoints (IP-based)
- Bot filtering op tracking endpoints
- Bcrypt password hashing voor admin accounts
- HSTS (HTTP Strict Transport Security)
- XSS preventie met HTML escaping
- CSRF bescherming via sameSite cookies
- SQL injection preventie via parameterized queries
- Content Security Policy via Helmet
- Strict CORS policy in productie
- Cache invalidatie bij data wijzigingen