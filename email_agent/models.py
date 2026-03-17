from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class EmailHeaders(BaseModel):
    from_: str
    to: str
    subject: str
    received: List[str]
    dkim_signature: Optional[str] = None
    return_path: Optional[str] = None

class AnalyzeRequest(BaseModel):
    email_id: str
    headers: EmailHeaders
    body_text: str
    body_html: Optional[str] = None
    timestamp: datetime
