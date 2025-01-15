from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models

class CustomUser(AbstractUser):
    """
    Custom User model that extends AbstractUser.
    """
    email = models.EmailField(unique=True)  # Make email unique for user identification
    # otp = models.IntegerField(null=True, blank=True)
    # otp_expiration = models.DateTimeField(null=True, blank=True)
    # mfa_enabled = models.BooleanField(default=False)  # Field to enable/disable MFA
    # mfa_secret = models.CharField(max_length=128, blank=True, null=True)  # MFA secret key for TOTP

    groups = models.ManyToManyField(
        Group,
        related_name="customuser_set",
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="customuser_set",
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
    )

    def __str__(self):
        return self.username
