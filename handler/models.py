from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=11)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phone"]
    objects = CustomUserManager()

    def __str__(self):
        return f"{self.name} ({self.email})"


class ModerationRequest(models.Model):
    CONTENT_TYPES = [
        ('text', 'Text'),
        ('image', 'Image'),
        ('mixed', 'Mixed')
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed')
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE, null=True, blank=True)
    content_type = models.CharField(max_length=10, choices=CONTENT_TYPES)
    content_hash = models.CharField(max_length=64)  # e.g. SHA256 hash
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)


class ModerationResult(models.Model):
    request = models.OneToOneField(ModerationRequest, on_delete=models.CASCADE)
    classification = models.CharField(max_length=20)
    confidence = models.FloatField()
    reasoning = models.TextField()
    llm_response = models.JSONField()


class NotificationLog(models.Model):
    request = models.ForeignKey(ModerationRequest, on_delete=models.CASCADE)
    channel = models.CharField(max_length=20)
    status = models.CharField(max_length=20)
    sent_at = models.DateTimeField()
