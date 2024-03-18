from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *

urlpatterns = [
        path('register/', UserCreateView.as_view(), name='user-registration'),
        path('login/', login, name='login'),
        path('registration/', registration, name='trial-registration'),
        path('csrf_token/', get_csrf_token, name='get_csrf_token'),
        path('upload-pdf/', upload_pdf, name='upload_pdf'),
        path('get-pdf/<str:consumer_number>/', get_kyc, name='get_pdf_by_consumer_number'),
        path('store_pdf/',store_pdf,name='store_pdf_in_S3'),
        path('retreive_pdf/',retrieve_pdf,name='Retreive_pdf_from_S3'),
        path('delete_pdf/',delete_pdf,name='Delete PDF'),
        path('update_pdf/',update_pdf,name='Update PDF'),
        ]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
