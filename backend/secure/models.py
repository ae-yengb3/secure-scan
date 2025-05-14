from django.db import models

# Create your models here.
class User(models.Model):
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    fullname = models.CharField(max_length=100)
    location = models.CharField(max_length=100)

    def __str__(self):
        return self.email

