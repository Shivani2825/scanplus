from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics, permissions
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, UploadedFile
from .serializers import UserSerializer, CustomUserSerializer, ChangeProfilePictureSerializer, ProfileImageSerializer, FileUploadSerializer
from django.utils.http import urlsafe_base64_decode
import PyPDF2
import tabula
from PIL import Image
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.http import JsonResponse
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_openai import OpenAI
import re
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from django.conf import settings
from django.core.mail import send_mail
from .serializers import ResetPasswordSerializer
from django.http import HttpResponse
from django.views import View


class FileUploadAPIView(generics.CreateAPIView):
    parser_classes = (MultiPartParser, FormParser)
    serializer_class = FileUploadSerializer

    def post(self, request, *args, **kwargs):
        token = request.headers.get('Authorization')
        user_id = request.headers.get('user')
        if not token:
            return JsonResponse({'error': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['user'] = user
            uploaded_file = serializer.validated_data["file"]
            content = self.extract_text_from_pdf(uploaded_file)
            serializer.validated_data['content'] = content
            saved_file = serializer.save()
            response_data = {
                'id': saved_file.id,
                'content': content,
            }
            response = Response(
                response_data,
                status=status.HTTP_201_CREATED
            )
        else:
            response = Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        return response

    def extract_text_from_pdf(self, uploaded_file):
        all_tables = []
        tables = tabula.read_pdf(uploaded_file, pages='all', guess=False, stream=True)
        for i, table in enumerate(tables, start=1):
            formatted_table = []
            for row in table.values:
                formatted_row = " | ".join(str(cell) for cell in row)
                formatted_table.append(formatted_row)
            all_tables.append(formatted_table)

        template = '''Extract Policy Details according you :
                like name of insurance company, name of plan, duration of policy, Policy Start Date ,Policy End Date, 
                policy number,Insure name , mobile number of person, email address of person,Vehicle Make & Model,Registration Number,
                Registration Date/year,Engine Number,Chassis Number and set the data into Insurance Company Name,
                Plan Name, Policy Duration, Policy Start Date, Policy End Date, Policy Number, Insured Person's Name,
                Insured Person's Mobile Number, Insured Person's Email Address, Vehicle Make & Model, Vehicle Registration Number,
                Vehicle Registration Date/Year, Vehicle Engine Number, Vehicle Chassis Number respectively
                From the text: {content} , and return 'nan' if any data does not exist.''' 
        
        llm = OpenAI(openai_api_key="")
        prompt = PromptTemplate.from_template(template)
        
        llm_chain = LLMChain(prompt=prompt, llm=llm)

        text = llm_chain.run(content=all_tables)
        policy_dict = {}
        for line in text.strip().split('\n'):
            try:
                key, value = line.split(': ', 1)
                policy_dict[key] = value
            except ValueError:
                continue

        policy_dict_no_numbers = {}
        for key, value in policy_dict.items():
            key_without_number = re.sub(r'^\d+\.\s*', '', key)
            policy_dict_no_numbers[key_without_number] = value

        policy_dict_filtered = {key: value for key, value in policy_dict_no_numbers.items() if value !='nan'}
        print(policy_dict_filtered)
        return policy_dict_filtered

class RegistrationAPIView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

class UserDetailsAPIView(APIView):
    def get(self, request, user_id):
        try:
            user = CustomUser.objects.get(id=user_id)
            serializer = CustomUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class LoginAPIView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        print(email)
        password = request.data.get('password')
        print(password)
        user = CustomUser.objects.filter(email=email).first()
        print(user)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'id': user.id,
                'name': user.username,
            })
        else:
            return Response({'error': 'Invalid credentials'}, status=401)

class ChangeProfilePictureAPIView(generics.UpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = ChangeProfilePictureSerializer
    permission_classes = [permissions.AllowAny]  

    def get_object(self):
        user_id = self.kwargs.get('user_id')
        return CustomUser.objects.get(id=user_id)

class UserProfileImageView(generics.RetrieveAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = ProfileImageSerializer
    permission_classes = [permissions.AllowAny]

    def get_object(self):
        user_id = self.kwargs.get('user_id')
        return CustomUser.objects.get(id=user_id)

class UpdateContentView(generics.UpdateAPIView):
    queryset = UploadedFile.objects.all()
    serializer_class = FileUploadSerializer

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        content_data = request.data.get('content')  # Get the content data from the request
        instance.content = content_data  # Assign the content data to the instance
        instance.save()  # Save the instance to update the content field
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def send_reset_password_email(request):
    email = request.data.get('email')
    if email:
        try:
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_password_link = f"{settings.FRONTEND_URL}/changepassword/{uid}/{token}/"
            send_mail(
                'Reset Password',
                f'Use the following link to reset your password: {reset_password_link}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            response_data = {
                'success': 'Password reset link sent successfully.',
                'uid': uid,
                'token': token,
                'reset_password_link': reset_password_link,
            }
            return JsonResponse(response_data)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'No user found with this email.'}, status=404)
    else:
        return JsonResponse({'error': 'Email field is required.'}, status=400)
    

from django.utils.encoding import force_bytes, force_str
@api_view(['POST'])
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        return JsonResponse({'error': 'Invalid reset password link.'}, status=400)
    
    if default_token_generator.check_token(user, token):
        new_password = request.data.get('password')
        if new_password:
            user.set_password(new_password)
            user.save()
            return JsonResponse({'success': 'Password reset successfully.'})
        else:
            return JsonResponse({'error': 'New password is required.'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid reset password link.'}, status=400)
    
class MediaListAPIView(View):
    def get(self, request, user_id):
        try:
            # Filter media based on user ID
            media_objects = UploadedFile.objects.filter(user_id=user_id)
        except UploadedFile.DoesNotExist:
            return JsonResponse({"error": "No media found for this user"}, status=404)

        # Serialize the media objects
        media_list = []
        for media_object in media_objects:
            media_list.append({
                "id": media_object.id,
                "filename": str(media_object.file),  # Assuming 'filename' is a field in your UploadedFile model
                # Add other fields you want to include
            })
            print("hello")

        return JsonResponse({"media": media_list})


class MediaAPIView(View):
    def get(self, request, user_id, media_id):
        try:
            media_object = UploadedFile.objects.filter(user_id=user_id, id=media_id).first()
        except UploadedFile.DoesNotExist:
            return HttpResponse("Media not found", status=404)

        if not media_object:
            return HttpResponse("Media not found for this user", status=404)

        response = HttpResponse(media_object.file, content_type='application/pdf')
        response['Content-Disposition'] = f'inline; filename="{media_object.filename}"'  
        return response
    
