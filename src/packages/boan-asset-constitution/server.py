import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="BoanClaw Asset Constitution", version="1.0.0")


class SLevelRule(BaseModel):
    level: str
    pattern: str
    keywords: list[str] = []
    description: str = ""


class Constitution(BaseModel):
    rules: list[SLevelRule] = []
    default_level: str = "S1"
    updated_at: str = ""


class ClassifyRequest(BaseModel):
    text: str
    filename: Optional[str] = None


class ClassifyResponse(BaseModel):
    level: str
    matched_rule: Optional[str] = None
    confidence: float = 1.0


class FeedbackRequest(BaseModel):
    text: str
    suggested_level: str
    reason: str = ""


class FeedbackRecord(BaseModel):
    id: str
    text: str
    suggested_level: str
    reason: str
    created_at: str


_constitution = Constitution(
    rules=[
        SLevelRule(
            level="S4",
            pattern=r"(password|secret|private.key|credential|api.key)",
            keywords=["password", "secret", "private_key", "credential"],
            description="Sensitive credentials",
        ),
        SLevelRule(
            level="S3",
            pattern=r"(ssn|social.security|\uc8fc\ubbfc\ub4f1\ub85d|\uac1c\uc778\uc815\ubcf4)",
            keywords=["ssn", "social_security", "pii"],
            description="Personally identifiable information",
        ),
        SLevelRule(
            level="S2",
            pattern=r"(internal|confidential|\ub300\uc678\ube44|\uc0ac\ub0b4)",
            keywords=["internal", "confidential"],
            description="Internal use only",
        ),
        SLevelRule(
            level="S1",
            pattern=r".*",
            keywords=[],
            description="Public",
        ),
    ],
    default_level="S1",
    updated_at=datetime.now(timezone.utc).isoformat(),
)

_feedback_store: list[FeedbackRecord] = []


@app.get("/constitution")
def get_constitution():
    return _constitution


@app.post("/constitution")
def update_constitution(body: Constitution):
    global _constitution
    body.updated_at = datetime.now(timezone.utc).isoformat()
    _constitution = body
    return {"status": "updated"}


@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    text = req.text.lower()
    if req.filename:
        text += " " + req.filename.lower()
    for rule in _constitution.rules:
        if re.search(rule.pattern, text, re.IGNORECASE):
            return ClassifyResponse(level=rule.level, matched_rule=rule.description)
    return ClassifyResponse(level=_constitution.default_level)


@app.post("/feedback")
def submit_feedback(req: FeedbackRequest):
    record = FeedbackRecord(
        id=str(uuid.uuid4()),
        text=req.text,
        suggested_level=req.suggested_level,
        reason=req.reason,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _feedback_store.append(record)
    return {"id": record.id, "status": "recorded"}


@app.get("/health")
def health():
    return {"status": "ok"}
