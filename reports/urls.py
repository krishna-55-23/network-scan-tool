from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('<int:job_id>/csv/', views.export_csv, name='export_csv'),
    path('<int:job_id>/pdf/', views.export_pdf, name='export_pdf'),
]
