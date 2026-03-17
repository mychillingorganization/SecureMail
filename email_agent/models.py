from datetime import datetime

from pydantic import BaseModel


class EmailHeaders(BaseModel):
    from_: str
    to: str
    subject: str
    received: list[str]
    dkim_signature: str | None = None
    return_path: str | None = None

class AnalyzeRequest(BaseModel):
    email_id: str
    headers: EmailHeaders
    body_text: str
    body_html: str | None = None
    timestamp: datetime
