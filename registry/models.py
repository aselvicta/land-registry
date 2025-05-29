from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class LandRecord(models.Model):
    owner_id = models.CharField(max_length=20, default='N/A')
    plot_number = models.CharField(max_length=50, default='N/A')
    district = models.CharField(max_length=50, default='N/A')
    region = models.CharField(max_length=50, default='N/A')
    size = models.CharField(max_length=20, default='N/A')
    title_deed_number = models.CharField(max_length=20, blank=True, null=True, default='N/A')
    record_hash = models.CharField(max_length=64, default='N/A')
    digital_signature = models.TextField(blank=True, null=True, default='N/A')
    timestamp = models.DateTimeField(default=timezone.now)
    issuer = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, default=None)

    class Meta:
        unique_together = ('owner_id', 'plot_number', 'district', 'region', 'size', 'title_deed_number')

    def __str__(self):
        return f"{self.owner_id} - {self.plot_number}"

class AuditLog(models.Model):
    action = models.CharField(max_length=100)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField()

    def __str__(self):
        return f"{self.action} by {self.user} at {self.timestamp}"