
# Honeypot API

## Description
This project is a FastAPI-based “honeypot” chat API that engages with suspected scammers, detects scam behavior, and extracts actionable intelligence (phone numbers, UPI IDs, phishing links, emails, and bank/card/account-like sequences). When a scam pattern is detected, it posts a final summary to a configured callback endpoint.

## Tech Stack
- Language/Framework: Python 3 + FastAPI
- Key libraries:
	- `uvicorn` (ASGI server)
	- `pydantic` (request validation)
	- `requests` (OpenRouter calls + final callback)
	- `rapidfuzz` (lightweight fuzzy matching for trigger detection)
	- `python-dotenv` (local `.env` support)
- LLM/AI models used (if any):
	- OpenRouter Chat Completions API (configurable via `OPENROUTER_MODEL`, defaults to `openai/gpt-4o-mini`)

## Setup Instructions
1. Clone the repository
2. Install dependencies
	 - `pip install -r requirements.txt`
3. Set environment variables
	 - Create a `.env` file in the project root (or set these in your deployment environment):
		 - `API_KEY` (required) — value expected in the `x-api-key` header
		 - `OPENROUTER_API_KEY` (required) — OpenRouter API key
		 - `OPENROUTER_MODEL` (optional) — e.g. `openai/gpt-4o-mini`

	 Note: the callback URL is currently configured in code as `GUVI_CALLBACK_URL` in `app/config.py`.
4. Run the application
	 - `uvicorn app.main:app --reload`

## API Endpoint
- URL: `https://your-deployed-url.com/honeypot`
- Method: `POST`
- Authentication: `x-api-key` header

### Request Body (JSON)
The request schema is validated by Pydantic.

Example:
```json
{
	"sessionId": "abc123-session-id",
	"message": {
		"sender": "scammer",
		"text": "Your account will be blocked. Share OTP to verify.",
		"timestamp": 1739999999
	},
	"conversationHistory": [],
	"metadata": {
		"channel": "sms",
		"language": "en",
		"locale": "en-IN"
	}
}
```

### Response Body (JSON)
```json
{
	"status": "success",
	"reply": "..."
}
```

## Approach

### How scams are detected
- The API maintains a per-session conversation store and builds a small “recent context” window.
- Scam behavior is flagged using scenario/keyword heuristics (e.g., urgency, account freeze language, verification/OTP-style requests). When scenarios are detected, `scamDetected` is set for the session.

### How intelligence is extracted
- Messages are scanned using regex + normalization heuristics to extract:
	- `phoneNumbers`
	- `upiIds`
	- `phishingLinks`
	- `emailAddresses`
	- `bankAccounts` (context-aware digit sequences and IBAN validation; includes Luhn check for card-like numbers)
- Suspicious keyword hits are also tracked to provide explainability.

### How engagement is maintained
- The “honeypot” persona responds like a cautious, confused user (banking context) to keep the attacker talking.
- A simple state machine adapts behavior as the conversation escalates (probe → trust → confusion → stall → evidence → disengage).
- Anti-echo rules reduce the risk of mirroring scam instructions; sanitization blocks the model from repeating sensitive digits and strips unnatural quote-wrapped replies.

### Final callback
When `scamDetected` is true and the conversation reaches a minimum length, the service posts a final summary payload to the configured callback endpoint. The payload includes `sessionId`, scam flag, message count, engagement duration, extracted intelligence, and agent notes.
