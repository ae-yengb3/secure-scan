from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from secure.serializers import UserSerializer, ScanSerializer
from secure.models import ScanResult
from secure.zap import *
import uuid
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
    url = request.data['targetUrl'].strip()
    scan_type = request.data['scanType'].strip()

    user = request.user

    if scan_type == "Vuln":
        if url is None:
            return Response({'error': 'url_not_found'}, status=status.HTTP_400_BAD_REQUEST)

        scan = start_zap_scan(url, user)

        if scan is None:
            return Response({'error': 'url_not_found'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Scan started successfully', 'scan_id': scan})
    elif scan_type == "Leak":
        if url is None:
            return Response({'error': 'url_not_found'}, status=status.HTTP_400_BAD_REQUEST)
        
        scan = start_leak_scan(url, user)

        if scan is None:
            return Response({'error': 'url_not_found'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Scan started successfully', 'scan_id': scan})
        
    elif scan_type == "Hybrid":
        pass
    else:
        return Response({'error': 'Invalid scan type'}, status=status.HTTP_400_BAD_REQUEST)

    return Response({})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_scans(request):
    scans = request.user.scans.all()
    serializer = ScanSerializer(scans, many=True)

    # update_scans(serializer.data)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_report(request):
    scans = request.user.scans.all()
    serializer = ScanSerializer(scans, many=True)

    reports = get_reports(serializer.data)

    return Response(reports)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_resolved(request):
    unique_id = request.data.get('unique_id')
    try:
        result = ScanResult.objects.get(unique_id=unique_id, scan__user=request.user)
        result.resolved = True
        result.save()
        return Response({'message': 'Marked as resolved'})
    except ScanResult.DoesNotExist:
        return Response({'error': 'Result not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_false_positive(request):
    unique_id = request.data.get('unique_id')
    try:
        result = ScanResult.objects.get(unique_id=unique_id, scan__user=request.user)
        result.marked_as_false_positive = True
        result.save()
        return Response({'message': 'Marked as false positive'})
    except ScanResult.DoesNotExist:
        return Response({'error': 'Result not found'}, status=status.HTTP_404_NOT_FOUND)
