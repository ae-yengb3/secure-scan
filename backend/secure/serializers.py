from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Scan, ScanResult

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'fullname', 'location']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class ScanSerializer(serializers.ModelSerializer):
    leak_data = serializers.JSONField(required=False)

    class Meta:
        model = Scan
        fields = ['user', 'url', 'scan_id', 'start_time', 'progress', 'leak_data'] 

    def create(self, validated_data):
        scan = Scan.objects.create(**validated_data)
        return scan


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'