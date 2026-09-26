from enum import Enum
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .detection_engine import detect, exposure_score, score_label

app = FastAPI(
    title="Sensitive Data Exposure API",
    version="1.0.0",
    description="Hackathon MVP API for detecting and protecting sensitive data in unintended locations.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanFinding(BaseModel):
    id: str
    type: str
    risk_level: str
    value: str
    start: int
    end: int
    reason: str


class ScanResponse(BaseModel):
    success: bool
    source: str
    text_length: int
    exposure_score: int = Field(ge=0, le=100)
    exposure_level: str
    detected_count: int
    findings: List[ScanFinding]


class RedactItem(BaseModel):
    id: Optional[str] = None
    type: str
    value: str
    start: int
    end: int


class MaskMode(str, Enum):
    BLACKOUT = "BLACKOUT"
    SMART_MASK = "SMART_MASK"
    REPLACE = "REPLACE"
    HIDE = "HIDE"


class RedactRequest(BaseModel):
    original_text: str
    selected_items: List[RedactItem]
    masking_mode: MaskMode


class RedactResponse(BaseModel):
    success: bool
    masking_mode: MaskMode
    original_text: str
    protected_text: str
    redacted_count: int


def _scan_response(text: str, source: str) -> ScanResponse:
    findings = detect(text)
    result = []
    for index, finding in enumerate(findings, start=1):
        result.append(ScanFinding(
            id=f"finding-{index}",
            type=finding.type,
            risk_level=finding.risk_level,
            value=finding.value,
            start=finding.start,
            end=finding.end,
            reason=finding.reason,
        ))
    score = exposure_score(findings)
    return ScanResponse(
        success=True,
        source=source,
        text_length=len(text),
        exposure_score=score,
        exposure_level=score_label(score),
        detected_count=len(result),
        findings=result,
    )


def _smart_mask(value: str, kind: str) -> str:
    if kind in {"API_KEY", "BEARER_TOKEN", "JWT_TOKEN", "PASSWORD"}:
        return "[SECRET]"
    if kind == "EMAIL":
        local, _, domain = value.partition("@")
        return (local[:1] + "***@" + domain) if local else "***@" + domain
    if kind == "PHONE":
        digits = "".join(c for c in value if c.isdigit())
        return "***" + digits[-4:] if len(digits) >= 4 else "***"
    if kind in {"FINANCIAL_NUMBER", "ID_NUMBER"}:
        compact = "".join(c for c in value if c.isdigit())
        return "****" + compact[-4:] if len(compact) >= 4 else "****"
    if kind == "IP_ADDRESS":
        parts = value.split(".")
        return ".".join(parts[:2] + ["***", "***"]) if len(parts) == 4 else "***"
    return "***"


def _replacement(item: RedactItem, mode: MaskMode) -> str:
    if mode == MaskMode.BLACKOUT:
        return "█" * max(1, item.end - item.start)
    if mode == MaskMode.SMART_MASK:
        return _smart_mask(item.value, item.type)
    if mode == MaskMode.REPLACE:
        return f"[REDACTED:{item.type}]"
    return ""


@app.get("/health")
def health():
    return {"status": "ok", "service": "sensitive-data-exposure-api", "version": app.version}


@app.post("/scan", response_model=ScanResponse)
async def scan(text: Optional[str] = Form(default=None), file: Optional[UploadFile] = File(default=None)):
    if text is None and file is None:
        raise HTTPException(status_code=400, detail="Provide either 'text' or 'file'.")
    if text is not None and file is not None:
        raise HTTPException(status_code=400, detail="Provide only one of 'text' or 'file'.")

    if file is not None:
        data = await file.read()
        try:
            content = data.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File must be UTF-8 text for this MVP.")
        source = file.filename or "uploaded-file"
    else:
        content = text or ""
        source = "text-input"

    return _scan_response(content, source)


@app.post("/redact", response_model=RedactResponse)
def redact(request: RedactRequest):
    text = request.original_text
    valid = []
    for item in request.selected_items:
            has_text = text is not None and text.strip() != ""
    has_file = file is not None

    if not has_text and not has_file:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'text' or 'file'."
        )

    if has_text and has_file:
        raise HTTPException(
            status_code=400,
            detail="Provide only one of 'text' or 'file'."
        )
        valid.append(item)

    # Work right-to-left so original positions stay valid.
    protected = text
    for item in sorted(valid, key=lambda x: x.start, reverse=True):
        protected = protected[:item.start] + _replacement(item, request.masking_mode) + protected[item.end:]

    return RedactResponse(
        success=True,
        masking_mode=request.masking_mode,
        original_text=text,
        protected_text=protected,
        redacted_count=len(valid),
    )
