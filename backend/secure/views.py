from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from secure.serializers import UserSerializer, ScanSerializer
from secure.zap import *
from datetime import datetime
# Create your views here.


@api_view(['POST'])
def create_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def start_scan(request):
    url = request.data['targetUrl']
    scan_id = start_zap_scan(url)
    user = request.user
    serializer = ScanSerializer(
        data={'user': user.id, 'url': url, "scan_id": scan_id, 'start_time': datetime.now()})
    if serializer.is_valid():
        serializer.save()
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    return Response({'scan_id': scan_id})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_scans(request):
    scans = request.user.scans.all()
    serializer = ScanSerializer(scans, many=True)

    update_scans(serializer.data)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_report(request):
    scans = request.user.scans.all()
    serializer = ScanSerializer(scans, many=True)

    print(serializer.data)

    reports = get_reports(serializer.data)
    return Response(reports)
