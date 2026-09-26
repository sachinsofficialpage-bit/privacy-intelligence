# Sensitive Data Exposure Backend

FastAPI MVP for the Satyabama Hackegenix problem statement: **Sensitive Data Where It Was Never Meant To Be**.

## Flow

`React → FastAPI → Detection Engine → JSON → React`

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Open Swagger at `http://localhost:8000/docs`.

## APIs

### GET `/health`

Returns service status.

### POST `/scan`

Use `multipart/form-data` with either:
- `text`: text to scan
- `file`: UTF-8 text file

Returns findings with stable IDs, type, risk level, value, start/end positions, reason, and an exposure score.

### POST `/redact`

JSON body:

```json
{
  "original_text": "Contact demo@example.com",
  "selected_items": [
    {
      "id": "finding-1",
      "type": "EMAIL",
      "value": "demo@example.com",
      "start": 8,
      "end": 24
    }
  ],
  "masking_mode": "SMART_MASK"
}
```

Supported modes:
- `BLACKOUT` — replaces the selected span with block characters.
- `SMART_MASK` — preserves useful context while hiding the sensitive part.
- `REPLACE` — uses `[REDACTED:TYPE]`.
- `HIDE` — removes the selected value.

## Detection types

Email, phone, API keys/tokens, password-like assignments, IPv4 addresses, ID-like numbers, and financial-number-like sequences.

Financial-number detection uses a Luhn check to reduce false positives. Patterns are intentionally conservative for an MVP and should not be treated as a production DLP engine.

## Demo data

Use synthetic values only during development and demos. Do not commit real credentials, tokens, personal data, or financial information.
