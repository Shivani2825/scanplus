from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth import get_user_model

 
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
 
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
 
        return self.create_user(email, password, **extra_fields)
 
class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30, blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
 
    objects = CustomUserManager()
 
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
 
    def __str__(self):
        return self.email
   
   
User = get_user_model()

class UploadedFile(models.Model):
    user = models.ForeignKey(User, related_name='files', on_delete=models.CASCADE,default=1)  # Add this line to associate UploadedFile with CustomUser
    file = models.FileField()
    content = models.TextField(blank=True)
    uploaded_on = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.uploaded_on.date()} - {self.file.name}"