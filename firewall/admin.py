from django.contrib import admin
from .models import ThreatLog, ChatSession, ChatMessage

@admin.register(ThreatLog)
class ThreatLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'prompt_text', 'threat_category', 'risk_score', 'is_blocked')
    list_filter = ('is_blocked', 'threat_category')
    search_fields = ('prompt_text', 'threat_category')

@admin.register(ChatSession)
class ChatSessionAdmin(admin.ModelAdmin):
    list_display = ('title', 'session_id', 'created_at')
    search_fields = ('title', 'session_id')

@admin.register(ChatMessage)
class ChatMessageAdmin(admin.ModelAdmin):
    list_display = ('session', 'sender', 'message', 'timestamp')
    list_filter = ('sender',)
    search_fields = ('message',)