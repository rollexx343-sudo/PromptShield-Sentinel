from django.db import models

class ThreatLog(models.Model):
    prompt_text = models.TextField()
    is_blocked = models.BooleanField(default=False)
    risk_score = models.FloatField()
    threat_category = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        status = "BLOCKED" if self.is_blocked else "CLEAN"
        return f"[{status}] - {self.threat_category} ({self.created_at.strftime('%H:%M:%S')})"
class ChatSession(models.Model):
    session_id = models.CharField(max_length=100, unique=True)
    title = models.CharField(max_length=200, default="New Chat")
    created_at = models.DateTimeField(auto_now_add=True)

class ChatMessage(models.Model):
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name="messages")
    sender = models.CharField(max_length=10) # 'user' ya 'ai'
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)