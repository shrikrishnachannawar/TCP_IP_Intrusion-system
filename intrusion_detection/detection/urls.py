from django.urls import path
from . import views

urlpatterns = [
    path('logs/', views.packet_logs, name='packet_logs'),
]
