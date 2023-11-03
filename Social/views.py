from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.contrib.auth.models import User
from .models import Profile, Post, Relationship
from .forms import PostForm, UserUpdateForm, ProfileUpdateForm
from django.core.cache import cache
from datetime import datetime, timedelta

@login_required(login_url='login')
def home(request):
    posts = Post.objects.all()
    if request.method == 'POST':
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.user = request.user
            post.save()
            return redirect('home')
    else:
        form = PostForm()

    context = {'posts': posts, 'form': form}
    return render(request, 'mainpage.html', context)


@login_required(login_url='login')
def delete(request, post_id):
    post = Post.objects.get(id=post_id)
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
