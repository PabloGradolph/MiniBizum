from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class CustomUserCreationForm(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].help_text = 'Introduce solo letras y no más de 35 caracteres.'
        self.fields['username'].validators = []
        self.fields['password1'].help_text = "Su contraseña debe contener al menos 8 caracteres y no puede ser completamente numérica."
        self.fields['password2'].help_text = ""
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']