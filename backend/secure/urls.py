from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView

urlpatterns = [
    path('create/user/', views.create_user, name='create-user'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('me/', views.get_user, name='get-user'),
    path('start/scan/', views.start_scan, name='start-scan'),
    path('scans/', views.get_scan, name='get-scan'),
]