from django.db import models
from django.contrib.auth import get_user_model
from django.utils.timezone import now, timedelta
import uuid

User = get_user_model()

class EncryptedFile(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="files")
    file = models.FileField(upload_to="encrypted_files/")
    filename = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

class FileShare(models.Model):
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name="shares")
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name="shared_files")
    permission = models.CharField(max_length=10, choices=[("view", "View"), ("download", "Download")])
    expires_at = models.DateTimeField()

class SecureLink(models.Model):
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, related_name="secure_links")
    link_id = models.UUIDField(default=uuid.uuid4, unique=True)
    expires_at = models.DateTimeField()
