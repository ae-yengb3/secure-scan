from django.db import models
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
    domain = models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    scan_id = models.CharField(max_length=100)
    start_time = models.DateTimeField(auto_now_add=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain

