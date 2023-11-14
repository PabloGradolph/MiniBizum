from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.db.models import Count, Sum
from django.contrib.auth.models import User
from .models import Transaction, Relationship
from .forms import PostForm, UserUpdateForm, ProfileUpdateForm
from django.conf import settings
from MiniBizum import algorithms
from .firma import generate_keys, sign_transaction, verify_signature, store_private_key

master_key = settings.MASTER_KEY

@login_required(login_url='login')
def home(request):
    # Desencriptamos los datos de las transacciones
    encrypted_transactions = Transaction.objects.all()
    transactions = []
    for transaction in encrypted_transactions:
        user_key = algorithms.load_user_key(transaction.user.id, master_key)
        decrypted_transaction = transaction
        decrypted_transaction.transaction_message = algorithms.decrypt_data(decrypted_transaction.transaction_message, user_key)
        decrypted_transaction.amount = algorithms.decrypt_data(decrypted_transaction.amount, user_key)
        transactions.append(decrypted_transaction)
        
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
            
            user_key = algorithms.load_user_key(request.user.id, master_key)  # Clave simétrica del usuario
            # TODO acceder a los users, y ahi coger el id del usuario que queremos porque sino no se almacena en su bd
            transaction = Transaction(
                user=request.user,
                transaction_type=transaction_type,
                recipient=recipient,
                transaction_message=algorithms.encrypt_data(str(transaction_message), user_key),
                amount=algorithms.encrypt_data(str(amount), user_key),
            )
            transaction.save()
            return redirect('home')
    else:
        form = PostForm()

    context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form}
    return render(request, 'main.html', context)


@login_required(login_url='login')
def edit(request):
    error = ''
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)

        if u_form.is_valid() and p_form.is_valid():
            u_form.save()

            amount_to_add = p_form.cleaned_data.get('amount_to_add')
            if amount_to_add is not None:
                profile = p_form.save(commit=False)
                profile.amount += amount_to_add
                profile.save()
            p_form.save()
            return redirect('profile', username=request.user.username)
        else:
            error = "Ese nombre de usuario ya está registrado en MiniBizum."
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)
        
    context = {'u_form': u_form, 'p_form': p_form, 'error': error}
    return render(request, 'social/editartwo.html', context)


@login_required(login_url='login')
def profile(request, username):
    user = get_object_or_404(User, username=username)
    encrypted_sent_transactions = Transaction.objects.filter(user=user)
    encrypted_received_transactions = Transaction.objects.filter(recipient=user)
    
    # Desciframos las transacciones enviadas por el usuario.
    decrypted_sent_transactions = []
    user_key = algorithms.load_user_key(user.id, master_key)
    for transaction in encrypted_sent_transactions:
        decrypted_transaction = transaction
        decrypted_transaction.transaction_message = algorithms.decrypt_data(decrypted_transaction.transaction_message, user_key)
        decrypted_transaction.amount = algorithms.decrypt_data(decrypted_transaction.amount, user_key)
        decrypted_sent_transactions.append(decrypted_transaction)
    
    # Desciframos las transacciones recibidas por el usuario.
    decrypted_received_transactions = []
    for transaction in encrypted_received_transactions:
        # La user_key cambia en función del usuario que ha enviado la transacción.
        user_key = algorithms.load_user_key(transaction.user.id, master_key)
        decrypted_transaction = transaction
        decrypted_transaction.transaction_message = algorithms.decrypt_data(decrypted_transaction.transaction_message, user_key)
        decrypted_transaction.amount = algorithms.decrypt_data(decrypted_transaction.amount, user_key)
        decrypted_received_transactions.append(decrypted_transaction)
        
    # Calcula el total enviado y recibido.
    total_sent = sum(int(transaction.amount) for transaction in decrypted_sent_transactions if transaction.transaction_type == 'enviar_dinero') or 0
    total_received = sum(int(transaction.amount) for transaction in decrypted_received_transactions if transaction.transaction_type == 'enviar_dinero') or 0

    # Obtiene el saldo actual del perfil del usuario.
    balance = user.profile.amount

    transactions = decrypted_sent_transactions + decrypted_received_transactions
    # Ordenamos por fecha de más reciente a más antigüa.
    transactions.sort(key=lambda x: x.timestamp, reverse=True)

    context = {
        'user': user,
        'transactions': transactions,
        'total_sent': total_sent,
        'total_received': total_received,
        'balance': balance,
    }
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
