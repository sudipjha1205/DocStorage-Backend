import jwt
import json
import boto3
import uuid
from django.conf import settings
from django.http import JsonResponse,HttpResponse,Http404, HttpResponseBadRequest
from django.middleware.csrf import get_token
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.core.files.uploadedfile import SimpleUploadedFile
from django.views.decorators.http import require_POST
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import ValidationError
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from .models import CustomUser,KYC,UploadedFile
from .serializers import UserSerializer
from .EmailBackend import EmailBackend


AWS_ACCESS_KEY = settings.AWS_ACCESS_KEY_ID
AWS_SECRET_KEY = settings.AWS_SECRET_ACCESS_KEY
AWS_REGION_NAME = settings.AWS_S3_REGION_NAME

JWT_SECRET_KEY = settings.SECRET_KEY

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name = AWS_REGION_NAME
    )

S3_BUCKET_NAME = 'docstoraage'


@csrf_exempt
@require_POST
def store_pdf(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')
        consumer_number = request.POST.get('consumer_number')
        uploader = request.POST.get('user')

        #Creating a file_name to store the pdf with a unique key
        file_name = f'{uploader}/{consumer_number}.pdf'
        try:
            uploaded_file = UploadedFile.objects.create(
                consumer_number = consumer_number,
                uploader = uploader,
                file_key = file_name
            )

            s3_client.upload_fileobj(pdf_file, S3_BUCKET_NAME, file_name)

            return JsonResponse({'message': 'File Uploaded Successfully!!'},status=200)
            #print("file uploaded")
        except Exception as e:
            if "Duplicate entry" in str(e):
                return JsonResponse({'message':'Already Present'},status=403)
            else:
                return JsonResponse({'message': "The error is '{}'".format(e)})
    else:
        return HttpResponseBadRequest('Only POST requests are allowed for this endpoint')
    

def retrieve_pdf(request):
    if request.method == 'GET':
        consumer_number = request.GET.get('consumer_number')
        uploader = request.GET.get('user')
        
        # Retrieve the file key from your database based on the consumer number and user
        # Assuming you have a model named 'UploadedFile'
        uploaded_file = UploadedFile.objects.filter(consumer_number=consumer_number, uploader=uploader).first()
        print("retreived from the database")

        # Check if the file exists and if the user has permission to access it
        if uploaded_file:
            print("inside the uploaded file if condition")
            consumer_number = uploaded_file.consumer_number
            file_name = f'{uploader}/{consumer_number}.pdf'

            # Generate a presigned URL to allow temporary access to the file
            url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET_NAME, 'Key': file_name},
                ExpiresIn=3600  # URL expiration time in seconds (adjust as needed)
            )

            return JsonResponse({'url': url})
        else:
            return HttpResponseBadRequest('File not found or you do not have permission to access it.')
    else:
        return HttpResponseBadRequest('Only GET requests are allowed for this endpoint.')


def delete_pdf(request):
    if request.method == 'GET':
        consumer_number = request.GET.get('consumer_number')
        uploader = request.GET.get('user')
        print("consumer number and user", consumer_number,uploader)
        
        try:
            try:
                deleted_file = UploadedFile.objects.filter(consumer_number=consumer_number, uploader=uploader).first()
                print(deleted_file)
            except Exception as e:
                print(e)

            if deleted_file:
                deleted_file.delete()
    
                file_name = f"{uploader}/{consumer_number}.pdf"
                
                s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=file_name)
                print("deleted the consumer {}".format(file_name))
                return JsonResponse({'message':'Object deleted Successfully'})
            else:
                return JsonResponse({'message':'consumer number is not present'})
        except Exception as e:
            print("Failed to delete due to error: ",e)
            return JsonResponse({'message':'Failed to delete the object'})
    else:
        return HttpResponseBadRequest("Only GET requests are allowed for this endpoint.")

@csrf_exempt
@require_POST
def update_pdf(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')
        consumer_number = request.POST.get('consumer_number')
        uploader = request.POST.get('user')

        #Creating a file_name to store the pdf with a unique key
        file_name = f'{uploader}/{consumer_number}.pdf'
        try:
            #row_to_be_updated = UploadedFile.objects.get(consumer_number=consumer_number)
            #row_to_be_updated.file_key = 

            s3_client.upload_fileobj(pdf_file, S3_BUCKET_NAME, file_name)

            return JsonResponse({'message': 'File Uploaded Successfully!!'},status=200)
            #print("file uploaded")
        except Exception as e:
            print(e)
            if "Duplicate entry" in str(e):
                return JsonResponse({'message':'Already Present'},status=403)
            else:
                return JsonResponse({'message': "The error is '{}'".format(e)})
    else:
        return HttpResponseBadRequest('Only POST requests are allowed for this endpoint')



class TokenObtainView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        user = EmailBackend().authenticate(request, email=email, password=password)
        print(f'Entered Password: {password}')
        print(f'Stored Hashed Password: {user}')

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        email = request.data.get('email', '')
        if get_user_model().objects.filter(email=email).exists():
            raise ValidationError({'error': 'User with this email already exists.'})

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            self.perform_create(serializer)
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        headers = self.get_success_headers(serializer.data)
        return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED, headers=headers)

def get_csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})

@api_view(['POST'])
def login(request):
    print("Inside login function")
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(username=email,password=password)
    print(user)

    try:
        if user is not None:
            refresh = RefreshToken.for_user(user)
            print("refresh", refresh)
            return JsonResponse({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
            }, status=status.HTTP_200_OK)
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        print(e)


@api_view(['POST'])
def registration(request):
    email = request.data.get('email')
    password = request.data.get('password')

    user = User.objects.create_user(username=email,password=password)
    user.save()
    
    if user is not None:
        return JsonResponse({'message': 'Registered Successfully'})
    return JsonResponse({'message': 'Registration Failed'})


@csrf_exempt
@require_POST
def upload_pdf(request):
    if request.method == 'POST':
        consumer_no = request.POST.get('consumerNo')
        pdf_file = request.FILES.get('pdfFile')


        if KYC.objects.filter(consumer_no=consumer_no).exists():
            return JsonResponse({'error': 'Consumer number already exists'}, status=403)
    
        if pdf_file:
            try:
                # Create a new instance of your PDF model
                pdf_document = KYC(consumer_no=consumer_no, pdf_file=pdf_file)
                pdf_document.full_clean()  # Validate the model fields, raises ValidationError if not valid
                pdf_document.save()

                return JsonResponse({'message': 'PDF uploaded successfully'})
            except ValidationError as e:
                return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)


def get_kyc(request,consumer_number):
    try:
        # Assuming you have a model named KYC with a 'pdf_file' field
        kyc_object = get_object_or_404(KYC, consumer_no=consumer_number)

        # Serve the PDF file
        response = HttpResponse(kyc_object.pdf_file.read(), content_type='application/pdf')
        response['Content-Disposition'] = f'inline; filename="{consumer_number}.pdf"'
        return response
    except Http404:
        return JsonResponse({'error': 'Consumer number not found'}, status=404)
