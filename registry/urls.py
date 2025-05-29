from django.urls import path
from . import views

urlpatterns = [
    path('', views.admin_dashboard, name='admin_dashboard'),
    path('register/', views.register_land, name='register_land'),
    path('verify/', views.verify_land, name='verify_land'),
    
]