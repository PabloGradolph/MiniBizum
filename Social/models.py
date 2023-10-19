from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone


# Modelo para los perfiles de los usuarios (añade atributos a los usuarios)
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, unique=True, null=False, blank=False)
    bio = models.TextField(default='Hola, MiniBizum!')
    image = models.ImageField(default='default.png')

    def __str__(self) -> str:
        return f"Perfil de {self.user.username}"

    def following(self):
        user_ids = Relationship.objects.filter(from_user=self.user).values_list('to_user_id', flat=True)
        return User.objects.filter(id__in=user_ids)
    
    def followers(self):
        user_ids = Relationship.objects.filter(to_user=self.user).values_list('from_user_id', flat=True)
        return User.objects.filter(id__in=user_ids)

# Perfil generado automáticamente cuando un usuario se registra.
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

post_save.connect(create_user_profile, sender=User)


# Modelo para las publicaciones de los usuarios.
class Post(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    content = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self) -> str:
        return self.content


class Relationship(models.Model):
    from_user = models.ForeignKey(User, related_name='relationships', on_delete=models.CASCADE)
    to_user = models.ForeignKey(User, related_name='related_to', on_delete=models.CASCADE)

    def __str__(self) -> str:
        return f'{self.from_user} to {self.to_user}'
