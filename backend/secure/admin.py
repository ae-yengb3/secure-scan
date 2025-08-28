from django.contrib import admin

from .models import User, Scan, ScanResult

# Register your models here.
admin.site.register(User)
admin.site.register(Scan)
admin.site.register(ScanResult)
