import json
import urllib.request
import urllib.error
import socket
from typing import Dict, Any

class LLMContentAnalyzer:
    def __init__(self, ollama_url: str = "http://ollama:11434/api/generate", model: str = "qwen2.5:3b"):
        self.ollama_url = ollama_url
        self.model = model
        self.timeout = 10
        self.max_retries = 2
        
        self.prompt_template = """You are a highly skilled cybersecurity analyst specializing in email threat detection.
            Task: Analyze the email below and classify it as either "safe" or "phishing".

            Classification Criteria:
            - "phishing": Emails that use psychological triggers (urgency, fear, curiosity) to make the recipient take an action. Look for:
                * Generic greetings or "No Subject".
                * Calls to action like "Renew now", "Verify account", "Click here to claim", or "Update settings".
                * Requests for personal information or immediate payment.
                * Unexpected winning notifications or account compromise alerts.
            - "safe": Legitimate communications, transactional receipts, meeting reminders, or internal business updates that lack high-pressure tactics or suspicious links. 

            Analyze carefully: Some phishing emails look like legitimate service notifications (e.g., subscription expiration). If the email is generic and asks for an immediate "Renew" or "Update", it is likely phishing.

            Email Subject: {subject}
            Email Body:
            {body}

            Return ONLY a valid JSON object:
            {{
            "classification": "safe" | "phishing",
            "confidence": <float>,
            "reasoning": "<concise explanation>"
            }}
        """

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
