import time
from collections import defaultdict

class TrafficMonitor:
    def __init__(self):
        self.request_log = defaultdict(list)
        self.MAX_REQUESTS_PER_MIN = 100
        self.MIN_TIME_BETWEEN = 0.1  # 100ms between requests

    def log_request(self, ip, timestamp):
        self._clean_old_entries(ip, timestamp)
        self.request_log[ip].append(timestamp)

    def is_abnormal(self, ip):
        timestamps = self.request_log[ip]

        # 1. Too many requests per minute
        if len(timestamps) > self.MAX_REQUESTS_PER_MIN:
            print(f"[⚠️ ABNORMAL] IP {ip} exceeded {self.MAX_REQUESTS_PER_MIN} req/min")
            return True

        # 2. Too frequent (bot-like behavior)
        if len(timestamps) >= 2:
            delta = timestamps[-1] - timestamps[-2]
            if delta < self.MIN_TIME_BETWEEN:
                print(f"[⚠️ ABNORMAL] IP {ip} sent requests too fast: {delta:.3f}s apart")
                return True

        return False

    def _clean_old_entries(self, ip, current_time, window=60):
        """Keep only recent requests within the time window (default 60 seconds)."""
        self.request_log[ip] = [
            t for t in self.request_log[ip] if current_time - t < window
        ]
