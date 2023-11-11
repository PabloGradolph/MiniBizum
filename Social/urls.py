from . import views
from django.urls import path


urlpatterns = [
    path('', views.home, name='home'),
    path('edit/', views.edit, name='edit'),
    path('profile/<str:username>/', views.profile, name='profile'),
    path('follow/<str:username>/', views.follow, name='follow'),
    path('unfollow/<str:username>/', views.unfollow, name='unfollow'),
]