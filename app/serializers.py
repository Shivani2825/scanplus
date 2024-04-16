from rest_framework import serializers
from .models import CustomUser, UploadedFile
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'username','password')
    def create(self, validated_data):
        # Hash the password before saving the user
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)
 
class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ['id', 'file', 'content', 'uploaded_on']

class CustomUserSerializer(serializers.ModelSerializer):
    files = UploadedFileSerializer(many=True, read_only=True)  # Serializer for related files

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'profile_image', 'files']

class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField(max_length=100)
    content = serializers.CharField(allow_blank=True, required=False, style={'base_template': 'textarea.html'})
    uploaded_on = serializers.DateTimeField(read_only=True)
    user = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all(), required=False)

    def create(self, validated_data):
        # Create and return a new UploadedFile instance using the validated data
        return UploadedFile.objects.create(
            file=validated_data['file'],
            content=validated_data.get('content', ''),
            user=validated_data.get('user')
        )

    def update(self, instance, validated_data):
        # Update and return an existing UploadedFile instance using the validated data
        instance.content = validated_data.get('content', instance.content)
        instance.file = validated_data.get('file', instance.file)
        instance.user = validated_data.get('user', instance.user)
        instance.save()
        return instance
 
class ChangeProfilePictureSerializer(serializers.Serializer):
    profile_image = serializers.ImageField()
 
    def update(self, instance, validated_data):
        instance.profile_image = validated_data.get('profile_image', instance.profile_image)
        instance.save()
        return instance
    
class ProfileImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['profile_image']

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=128)
    token = serializers.CharField(max_length=100)
    uidb64= serializers.CharField(max_length=100)

    def validate(self, attrs):
        uidb64 = attrs.get('uidb64')
        token = attrs.get('token')
        try:
            # Decode uidb64b64 to get the user ID
            uidb64 = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uidb64)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise serializers.ValidationError('Invalid reset password link.')

        # Check if the token is valid for the user
        if not default_token_generator.check_token(user, token):
            raise serializers.ValidationError('Invalid reset password link.')

        return attrs