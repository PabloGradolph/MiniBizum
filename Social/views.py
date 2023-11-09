from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.db.models import Count
from django.contrib.auth.models import User
from .models import Transaction, Relationship
from .forms import PostForm, UserUpdateForm, ProfileUpdateForm


@login_required(login_url='login')
def home(request):
    transactions = Transaction.objects.all()
    user_balance = request.user.profile.amount
    top_users = User.objects.annotate(transaction_count=Count('posts')).order_by('-transaction_count')[:3]
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            transaction_type = form.cleaned_data['transaction_type']
            recipient = form.cleaned_data['recipient_username']
            transaction_message = form.cleaned_data['transaction_message']
            amount = form.cleaned_data['amount']

            if transaction_type == 'enviar_dinero':
                
                if amount > user_balance:
                    error = 'Saldo insuficiente para realizar la transacción'
                    context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form, 'error': error}
                    return render(request, 'main.html', context)
                else:
                    try:
                        recipient = User.objects.get(username=recipient)
                    except User.DoesNotExist:
                        error = 'El usuario seleccionado no existe'
                        context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form, 'error': error}
                        return render(request, 'main.html', context)
                    else:
                        request.user.profile.amount -= amount
                        request.user.profile.save()
                        recipient.profile.amount += amount
                        recipient.profile.save()

            else:
                try:
                    recipient = User.objects.get(username=recipient)
                except User.DoesNotExist:
                    error = 'El usuario seleccionado no existe'
                    context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form, 'error': error}
                    return render(request, 'main.html', context)
                
            transaction = Transaction(
                user=request.user,
                transaction_type=transaction_type,
                recipient=recipient,
                transaction_message=transaction_message,
                amount=amount,
            )
            transaction.save()
            return redirect('home')
    else:
        form = PostForm()

    context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form}
    return render(request, 'main.html', context)


@login_required(login_url='login')
def delete(request, post_id):
    post = Transaction.objects.get(id=post_id)
    post.delete()
    
    # Obtén la URL de la página anterior
    referer = request.META.get('HTTP_REFERER')
        
    if 'profile' in referer:
        username = request.user.username
        profile_url = reverse('profile', kwargs={'username': username})
        return redirect(profile_url)
    else:
        return redirect('home')


@login_required(login_url='login')
def edit(request):
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)

        if u_form.is_valid() and p_form.is_valid():
            u_form.save()
            p_form.save()
            return redirect('home')
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm()
        
    context = {'u_form': u_form, 'p_form': p_form}
    return render(request, 'social/editar.html', context)


@login_required(login_url='login')
def profile(request, username):
    user = User.objects.get(username=username)
    posts = user.posts.all()
    context = {'user': user, 'posts':posts}
    return render(request, 'social/profile.html', context)


@login_required(login_url='login')
def follow(request, username):
    current_user = request.user
    to_user = User.objects.get(username=username)
    to_user_id = to_user
    rel = Relationship(from_user=current_user, to_user=to_user_id)
    rel.save()
    profile_url = reverse('profile', kwargs={'username': username})
    return redirect(profile_url)


@login_required(login_url='login')
def unfollow(request, username):
    current_user = request.user
    to_user = User.objects.get(username=username)
    rel = Relationship.objects.get(from_user=current_user.id, to_user=to_user.id)
    rel.delete()
    profile_url = reverse('profile', kwargs={'username': username})
    return redirect(profile_url)
