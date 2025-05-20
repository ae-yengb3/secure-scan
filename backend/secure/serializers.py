from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Scan

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'fullname', 'location']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ['user', 'url', 'status', 'scan_id', 'start_time']

    def create(self, validated_data):
        scan = Scan.objects.create(**validated_data)
        return scan