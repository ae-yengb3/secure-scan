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
    class Meta:
        model = Scan
        fields = ["url", "user", "scan_id", "zap_scan_id",
                  "progress", "remark", "start_time", "end_time", "timestamp"]

    def create(self, validated_data):
        scan = Scan.objects.create(**validated_data)
        return scan


class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__'
