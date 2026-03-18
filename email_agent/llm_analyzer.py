"""Single-email LLM classifier.

Supported providers: Groq (primary) and Google Gemma (fallback).
Input: --input-file (JSON with sender/subject/body or Subject/Content text) or CLI fields.
"""

import argparse
import json
import urllib.request
import urllib.error
import socket
from typing import Dict, Any

class LLMContentAnalyzer:
    def __init__(self, ollama_url: str = "http://ollama:11434/api/generate", model: str = "qwen2.5:3b"):
        self.ollama_url = ollama_url
        self.model = model
        self.temperature = float(temperature)

    def analyze(self, email: EmailInput) -> AnalyzeResult:
        raise NotImplementedError


class GroqContentAnalyzer(BaseAnalyzer):
    provider = "groq"

    def __init__(self, api_key: str, model: str, temperature: float = DEFAULT_TEMPERATURE):
        super().__init__(model=model, temperature=temperature)
        self.api_key = api_key
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.timeout = 30
        self.max_retries = 2
        
        self.prompt_template = """You are a highly skilled cybersecurity analyst specializing in email threat detection.

Task: Analyze the email fields below and classify it as either "safe" or "phishing".

Classification Criteria:
- "phishing" (Treat this label as a catch-all for ANY malicious, scam, or dangerous email):
    * Emails aiming to steal credentials, fake brand identities, or demand payment.
    * Unsolicited SPAM or SCAM emails offering fake products or lottery wins.
    * Emails containing suspicious links combined with psychological triggers like urgency or fear.
- "safe":
    * Strictly legitimate communications, transactional receipts, meeting reminders, or verified business newsletters.

Sender:
{sender}

Subject:
{subject}

Email Body:
{body}

Important:
- Do not output chain-of-thought.
- Return only a short final reasoning sentence.

Return ONLY a valid JSON object with no extra text:
{{
  "classification": "safe" | "phishing",
  "confidence": <float 0.0-1.0>,
    "reasoning": "<concise explanation>"
}}"""

    def analyze(self, subject: str, body: str) -> Dict[str, Any]:
        prompt = self.prompt_template.format(subject=subject, body=body)
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(self.ollama_url, data=data, headers={"Content-Type": "application/json"})
        
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = json.loads(response.read().decode('utf-8'))
                    response_text = result.get("response", "{}")
                    
                    try:
                        parsed_intent = json.loads(response_text)
                        
                        # Normalize and ensure schema
                        return {
                            "classification": parsed_intent.get("classification", "unknown"),
                            "confidence": float(parsed_intent.get("confidence", 0.0)),
                            "reasoning": str(parsed_intent.get("reasoning", ""))
                        }
                    except (json.JSONDecodeError, ValueError):
                        return {
                            "classification": "unknown",
                            "confidence": 0.0,
                            "reasoning": f"Failed to parse LLM response: {response_text}"
                        }
            except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
                if attempt == self.max_retries:
                    return {
                        "classification": "unknown",
                        "confidence": 0.0,
                        "reasoning": f"LLM API request failed after {self.max_retries} retries: {str(e)}"
                    }
        
        return {
            "classification": "unknown",
            "confidence": 0.0,
            "reasoning": "Unknown error occurred"
        }
