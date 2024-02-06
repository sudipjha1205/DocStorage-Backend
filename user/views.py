import json
from django.http import JsonResponse,HttpResponse,Http404
from django.middleware.csrf import get_token
from rest_framework.exceptions import ValidationError
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny
from .models import CustomUser,KYC
from .serializers import UserSerializer
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from .EmailBackend import EmailBackend
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.core.files.uploadedfile import SimpleUploadedFile
from django.views.decorators.http import require_POST
from django.http import HttpResponse
from django.shortcuts import get_object_or_404

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
    email = request.data.get('email')
    password = request.data.get('password')

    user = authenticate(username=email,password=password)
    print(user)

    if user is not None:
        refresh = RefreshToken.for_user(user)
        return JsonResponse({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }, status=status.HTTP_200_OK)
    else:
        return JsonResponse({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


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
