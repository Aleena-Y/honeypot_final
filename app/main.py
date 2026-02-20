import logging


from fastapi import FastAPI, Header, HTTPException
from app.schemas import RequestSchema
from app.config import API_KEY, OPENROUTER_API_KEY
from app.scam_detector import detect_scam, detect_scam_scenarios
from app.agent import generate_reply
from app.intelligence import extract_intelligence
from app.memory import get_session
from app.callback import send_final_callback

app = FastAPI()
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)s:%(name)s:%(message)s"
)


@app.on_event("startup")
def validate_openrouter_config():
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is not set")


@app.post("/honeypot")
def honeypot(data: RequestSchema, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session = get_session(data.sessionId)
    session["messages"].append(data.message.dict())

    recent_context = " ".join(
        str(msg.get("text", ""))
        for msg in (session.get("messages") or [])[-5:]
    )
    detected_scenarios = detect_scam_scenarios(recent_context)
    if detected_scenarios:
        session["scamDetected"] = True

        # Merge detected scenarios into intelligence for explainable callbacks.
        intelligence = session.get("intelligence") or {}
        existing = intelligence.get("scamScenarios") or {}
        merged = {k: list(v) for k, v in existing.items()} if isinstance(existing, dict) else {}
        for scenario, matches in detected_scenarios.items():
            merged_matches = set(merged.get(scenario, []))
            merged_matches.update(matches)
            merged[scenario] = sorted(merged_matches)
        intelligence["scamScenarios"] = merged
        session["intelligence"] = intelligence

        extract_intelligence(session["messages"], session["intelligence"])

    try:
        reply = generate_reply(session["messages"])

    except Exception as e:
        logger.exception("LLM failed, using fallback")
        print("🔥 REAL LLM ERROR:", repr(e))
        reply = "I am not understanding this properly. Can you explain again?"



    if session["scamDetected"] and len(session["messages"]) >= 8:
        send_final_callback(data.sessionId, session)

    return {"status": "success", "reply": reply}
