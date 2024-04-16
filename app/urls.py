from django.urls import path
from .views import RegistrationAPIView, LoginAPIView, FileUploadAPIView, UserDetailsAPIView, ChangeProfilePictureAPIView, UserProfileImageView, UpdateContentView, send_reset_password_email, reset_password,MediaAPIView,MediaListAPIView

urlpatterns = [
    # Other URL patterns...
    path('register/', RegistrationAPIView.as_view(), name='register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('file-upload/', FileUploadAPIView.as_view(), name='file-upload'),
    path('user/<int:user_id>/', UserDetailsAPIView.as_view(), name='user-details'),
    path('user/change-profile-picture/<int:user_id>/', ChangeProfilePictureAPIView.as_view(), name='change-profile-picture'),
    path('user/profile-image/<int:user_id>/', UserProfileImageView.as_view(), name='user-profile-image'),
    path('update-content/<int:pk>/', UpdateContentView.as_view(), name='update-content'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='password_reset'),
    path('send-reset-password-email/', send_reset_password_email, name='send-reset-password-email'),
    path('user/<int:user_id>/media/', MediaListAPIView.as_view(), name='media-list'),
    path('user/<int:user_id>/media/<int:media_id>/', MediaAPIView.as_view(), name='media-view'),

]

 