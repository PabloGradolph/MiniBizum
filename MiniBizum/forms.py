from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class CustomUserCreationForm(UserCreationForm):
    """
    A custom form for user registration that adds specific requirements for our project.
    It modifies the default UserCreationForm to include a phone field and customizes help texts and labels.
    """

    phone = forms.CharField(label='Teléfono', max_length=9, required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Customize help texts and labels for the form fields
        self.fields['username'].help_text = 'Introduce un máximo de 15 caracteres.'
        self.fields['username'].label = 'Nombre de usuario'
        self.fields['username'].validators = []
        self.fields['password1'].help_text = ("Su contraseña debe contener al menos 8 caracteres con letras, números y "
                                              "al menos un caracter especial.")
        self.fields['password1'].label = 'Contraseña'
        self.fields['password2'].help_text = ""
        self.fields['password2'].label = 'Repetir contraseña'
        self.fields['email'].label = 'Correo electrónico'

    class Meta:
        model = User
        fields = ['username', 'email', 'phone', 'password1', 'password2']
