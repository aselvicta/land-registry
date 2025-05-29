from .models import AuditLog
from django.contrib.auth.models import User

def log_action(user, action, details):
    AuditLog.objects.create(user=user, action=action, details=details)