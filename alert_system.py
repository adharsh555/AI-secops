import smtplib
from datetime import datetime

class AlertSystem:
    def __init__(self):
        self.quarantine_log = []

    def quarantine(self, request, reason, payload=None):
        entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip': request.remote_addr,
            'payload': payload,
            'reason': reason
        }

        self.quarantine_log.append(entry)
        self.send_alert(entry)

    def send_alert(self, entry):
        # Print alert (replace with email/SMS in production)
        print(f"\n🚨 SECURITY ALERT 🚨")
        print(f"Time: {entry['timestamp']}")
        print(f"IP: {entry['ip']}")
        print(f"Reason: {entry['reason']}")
        payload = entry.get('payload')
        if payload:
            print(f"Payload: {payload[:200]}...\n")
        else:
            print("No payload provided.\n")

        # Example email code (safe & formatted)
        '''
        try:
            msg = f"""Subject: AI-SecOps Alert

🚨 SECURITY ALERT 🚨
Time: {entry['timestamp']}
IP: {entry['ip']}
Reason: {entry['reason']}
Payload: {entry['payload'][:500] if entry['payload'] else 'None'}"""

            with smtplib.SMTP('smtp.example.com', 587) as server:
                server.starttls()
                server.login('your_email@example.com', 'your_password')
                server.sendmail(
                    'your_email@example.com',
                    'admin@example.com',
                    msg
                )
        except Exception as e:
            print(f"[Email Error] Failed to send alert: {e}")
        '''
