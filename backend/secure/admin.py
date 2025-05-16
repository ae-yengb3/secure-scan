from django.contrib import admin

from .models import User, Scan

# Register your models here.
admin.site.register(User)
admin.site.register(Scan)
