from django import forms
from django.contrib.auth.models import User
from .models import Profile

class PostForm(forms.Form):
    
    TRANSACTION_CHOICES = [
        ('enviar_dinero', 'Enviar dinero'),
        ('solicitar_dinero', 'Solicitar dinero'),
    ]
    
    transaction_type = forms.ChoiceField(
        choices=TRANSACTION_CHOICES,
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'}),
    )

    recipient_username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nombre de usuario destinatario'}),
    )

    transaction_message = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': '3', 'placeholder': 'Ingrese un mensaje relacionado con la transacción'}),
        required=False,
    )

    amount = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        required=False,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Cantidad de dinero'}),
    )

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'username']

class ProfileUpdateForm(forms.ModelForm):
    amount_to_add = forms.DecimalField(max_digits=10, decimal_places=2, required=False, min_value=0)
    class Meta:
        model = Profile
        fields = ['image', 'bio']
        widgets = {
            'image': forms.FileInput(attrs={'class': 'hide-current-image'})
        }