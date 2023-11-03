from . import views
from django.urls import path


urlpatterns = [
    path('', views.home, name='home'),
    path('delete/<int:post_id>', views.delete, name='delete'),
    path('edit/', views.edit, name='edit'),
    path('profile/<str:username>/', views.profile, name='profile'),
    path('follow/<str:username>/', views.follow, name='follow'),
    path('unfollow/<str:username>/', views.unfollow, name='unfollow'),
]