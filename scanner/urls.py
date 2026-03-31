from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/start/', views.start_scan, name='start_scan'),
    path('scan/<int:job_id>/status/', views.scan_status, name='scan_status'),
    path('scan/<int:job_id>/result/', views.scan_result, name='scan_result'),
    path('scan/<int:job_id>/delete/', views.delete_scan, name='delete_scan'),
    path('history/', views.scan_history, name='history'),
]
