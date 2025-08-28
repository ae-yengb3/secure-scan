from django.db import models
import uuid
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not password:
            raise ValueError('The Password field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100)
    fullname = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["password", "fullname"]

    def __str__(self):
        return self.email
    

class Scan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    url = models.CharField(max_length=100)
    scan_id = models.CharField(max_length=100, primary_key=True, default=uuid.uuid4)
    zap_scan_id = models.CharField(max_length=100, null=True, blank=True)
    progress = models.IntegerField(default=0)
    remark = models.TextField(blank=True)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url


class ScanResult(models.Model):
    RISK_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
        ('Informational', 'Informational'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='results')
    id = models.AutoField(primary_key=True)
    unique_id = models.CharField(max_length=100, blank=True)
    alert_name = models.CharField(max_length=255)
    risk = models.CharField(max_length=20, choices=RISK_CHOICES)
    confidence = models.CharField(max_length=20)
    url = models.URLField()
    description = models.TextField()
    solution = models.TextField(blank=True)
    reference = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    attack = models.TextField(blank=True)
    param = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    marked_as_false_positive = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.alert_name} - {self.risk}"

