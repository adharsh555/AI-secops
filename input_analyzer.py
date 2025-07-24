import re
from transformers import pipeline

class InputAnalyzer:
    def __init__(self):
        # Rule-based malicious patterns
        self.patterns = [
            r"ignore.{0,20}previous.{0,20}instructions",
            r"(?:user|system|prompt).{0,10}override",
            r"secret.{0,10}(?:key|token|password|credentials)",
            r";\s*(?:rm|drop|delete|shutdown|format|mkfs)",
            r"(?:exec|eval|import|subprocess|os\.system)",
            r"(?:sqlmap|union\s+select|--\s+)",  # SQL injection
        ]

        # ML classifier for sentiment analysis (can be swapped later for intent model)
        self.classifier = pipeline(
            "text-classification", 
            model="distilbert-base-uncased-finetuned-sst-2-english"
        )

    def is_malicious(self, text: str) -> bool:
        if not text:
            return False

        # Rule-based scan
        for pattern in self.patterns:
            if re.search(pattern, text, re.IGNORECASE):
                print(f"[!] Regex match found: {pattern}")
                return True

        # ML-based sentiment check
        try:
            result = self.classifier(text[:512])[0]  # Truncate for model
            print(f"[DEBUG] Classifier result: {result}")
            if result['label'] == 'NEGATIVE' and result['score'] > 0.85:
                return True
        except Exception as e:
            print(f"[ERROR] ML classification failed: {e}")
            # Fail-safe: Do not block if model fails
            return False

        return False
