# Scam Detector

Message analyzer with accounts, Google sign-in, history and a dashboard.
Frontend: plain HTML / CSS / JavaScript. Backend: Flask + MySQL.

```
scam-detector/
├── app.py                  Flask API + page server
├── schema.sql              MySQL tables (users, analyses, password_resets)
├── requirements.txt
├── .env.example            copy to .env
├── templates/
│   └── index.html          all screens (login, register, forgot/reset, analyzer)
└── static/
    ├── css/style.css
    ├── js/
    │   ├── i18n.js         EN / KN / HI text for the whole interface
    │   ├── detector.js     rule engine + URL analysis (no DOM, testable)
    │   ├── detector.cases.js   test messages
    │   └── app.js          UI logic, calls /api/*
    └── tests.html          runs the detector test cases in the browser
```

## Setup

1. **Python packages**
   ```bash
   python -m venv venv
   venv\Scripts\activate            # Windows   (macOS/Linux: source venv/bin/activate)
   pip install -r requirements.txt
   ```
2. **Database**
   ```bash
   mysql -u root -p < schema.sql
   ```
3. **Settings** – copy `.env.example` to `.env`, then set `SECRET_KEY` (command inside the file),
   `DB_USER` and `DB_PASSWORD`.
4. **Run**
   ```bash
   python app.py
   ```
   Open <http://localhost:5000>. Use `localhost`, not `127.0.0.1` (matters for Google login).

## Google sign-in (optional)

1. Google Cloud Console → APIs & Services → Credentials → **Create credentials → OAuth client ID → Web application**.
2. Under **Authorized JavaScript origins** add `http://localhost:5000` (and your real domain later).
3. Copy the Client ID into `GOOGLE_CLIENT_ID` in `.env` and restart Flask.

No client secret is needed. Without a Client ID, the Google button stays visible but shows a "not set up" message.

## Forgot password

The link is e-mailed if you fill in the `SMTP_*` settings. Without them, the link is printed in the
Flask console, which is enough for local testing.

## Testing the detector

Open <http://localhost:5000/static/tests.html>. To add a case, append an entry to
`static/js/detector.cases.js`. Thresholds (safe < 25, suspicious 25–49, scam ≥ 50) and the rule
weights are at the top of `static/js/detector.js`.

## Notes

- Passwords are hashed with Werkzeug (scrypt). Sessions use an HttpOnly, SameSite=Lax cookie;
  "Remember me" keeps it for 30 days. API writes require an `X-Requested-With` header as CSRF protection.
- The detector is rule-based, so it will miss some scams and flag some genuine messages.
  Treat the result as a warning sign, not a verdict.
- Not included yet: login rate limiting (try `Flask-Limiter`), e-mail verification at sign-up,
  and the optional AI-assisted explanation.
- Signing in with Google for an e-mail that already has a password account removes that password
  (sign-up e-mails aren't verified). The owner can set a new one with "Forgot password".
- For production, run behind HTTPS with `COOKIE_SECURE=1`, `FLASK_DEBUG=0`, and a WSGI server such as gunicorn or waitress.
