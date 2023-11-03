from django import forms
from django.contrib.auth.models import User
from .models import Post, Profile

class PostForm(forms.ModelForm):
    content = forms.CharField(widget=forms.Textarea(attrs={
        'class': 'form-control w-100', 'id': 'contentsBox', 'rows': '3',
        'placeholder': '¿Qué está ocurriendo?'
    }))

    image = forms.ImageField(required=False, widget=forms.ClearableFileInput(attrs={
        'class': 'form-control-file',
    }))

    class Meta:
        model = Post
        fields = ['content', 'image']

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'username']

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['image', 'bio']