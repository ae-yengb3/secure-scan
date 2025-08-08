from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('create/user/', views.create_user, name='create-user'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('me/', views.get_user, name='get-user'),
    path('start/scan/', views.start_scan, name='start-scan'),
    path('scans/', views.get_scans, name='get-scan'),
    path('reports/', views.get_report, name='get-reports'),
]