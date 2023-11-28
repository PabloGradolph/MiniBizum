from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.db.models import Count
from django.contrib.auth.models import User
from django.db.models.query import QuerySet
from django.http import HttpRequest
from .models import Transaction, Relationship
from .forms import PostForm, UserUpdateForm, ProfileUpdateForm
from django.conf import settings
from MiniBizum import algorithms
from .firma import sign_transaction, verify_signature, get_user_key_path, decrypt_private_key
from .certificate import is_certificate_valid, get_user_public_key



master_key = settings.MASTER_KEY


@login_required(login_url='login')
def home(request):
    """
    Home page view, displaying user's transactions and allowing them to post new transactions.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The rendered home page.
    """
    user = get_object_or_404(User, username=request.user.username)

    # Verify the authenticity of the user's certificate
    if not is_certificate_valid(user):
        return render(request, 'error.html', {'error': 'Certificado no válido'})
    
    # Decrypt transaction data and verify all signatures and certificates
    transactions = decrypt_transactions(request, Transaction.objects.all())
    transactions = verify_all_signatures_and_certificates(request, transactions)
        
    user_balance = request.user.profile.amount
    top_users = User.objects.annotate(transaction_count=Count('posts')).order_by('-transaction_count')[:3]

    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            # Extract data from the valid form
            transaction_type = form.cleaned_data['transaction_type']
            recipient = form.cleaned_data['recipient_username']
            transaction_message = form.cleaned_data['transaction_message']
            amount = form.cleaned_data['amount']

            # Process the transaction and handle the result
            process_transaction_result = process_transaction(request, transaction_type, recipient, transaction_message, amount, user_balance)
            if process_transaction_result != 'success':
                # Display an error if the transaction processing fails
                context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form, 'error': process_transaction_result}
                return render(request, 'main.html', context)
            
            # Redirect to the homepage after a successful transaction
            return redirect('home')
    else:
        form = PostForm()

    context = {'user_balance': user_balance, 'top_users': top_users, 'transactions': transactions, 'form': form}
    return render(request, 'main.html', context)


@login_required(login_url='login')
def edit(request):
    """
    View for editing user and profile information.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: The rendered edit profile page.
    """
    error = ''
    if request.method == 'POST':
        u_form = UserUpdateForm(request.POST, instance=request.user)
        p_form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user.profile)

        if u_form.is_valid() and p_form.is_valid():
            u_form.save()

            # Update the profile amount if 'amount_to_add' is provided
            amount_to_add = p_form.cleaned_data.get('amount_to_add')
            if amount_to_add is not None:
                profile = p_form.save(commit=False)
                profile.amount += amount_to_add
                profile.save()
            p_form.save()

            # Redirect to the user's profile page after updating
            return redirect('profile', username=request.user.username)
        else:
            error = "Ese nombre de usuario ya está registrado en MiniBizum."
    else:
        u_form = UserUpdateForm(instance=request.user)
        p_form = ProfileUpdateForm(instance=request.user.profile)
        
    context = {'u_form': u_form, 'p_form': p_form, 'error': error}
    return render(request, 'social/editar.html', context)


@login_required(login_url='login')
def profile(request, username: str):
    """
    Display the user's profile page with their transactions.

    Args:
        request: The HTTP request object.
        username (str): The username of the profile to be displayed.

    Returns:
        HttpResponse: The profile page with transaction details.
    """
    user = get_object_or_404(User, username=username)

    # Verify the authenticity of the user's certificate
    if not is_certificate_valid(user):
        return render(request, 'error.html', {'error': 'Certificado no válido'})
    
    # Extract the public key from the user's certificate
    user_public_key = get_user_public_key(user)
    if not user_public_key:
        return render(request, 'error.html', {'error': 'Clave pública no disponible'})
    
    # Decrypt the transactions sent by the user and verify the signature and the certificate
    decrypted_sent_transactions = decrypt_transactions(request, Transaction.objects.filter(user=user))
    decrypted_sent_transactions = verify_all_signatures_and_certificates(request, decrypted_sent_transactions)

    # Decrypt the transactions received by the user and verify the signature and the certificate
    decrypted_received_transactions = decrypt_transactions(request, Transaction.objects.filter(recipient=user))
    decrypted_sent_transactions = verify_all_signatures_and_certificates(request, decrypted_sent_transactions)
        
    # Calculate total amount sent and received
    total_sent = sum(int(transaction.amount) for transaction in decrypted_sent_transactions if transaction.transaction_type == 'enviar_dinero') or 0
    total_received = sum(int(transaction.amount) for transaction in decrypted_received_transactions if transaction.transaction_type == 'enviar_dinero') or 0

    # Get the current balance of the user's profile
    balance = user.profile.amount

    # Combine and sort transactions by date, most recent first
    transactions = sorted(decrypted_sent_transactions + decrypted_received_transactions, key=lambda x: x.timestamp, reverse=True)

    context = {
        'user': user,
        'transactions': transactions,
        'total_sent': total_sent,
        'total_received': total_received,
        'balance': balance,
    }
    return render(request, 'social/profile.html', context)


@login_required(login_url='login')
def follow(request, username: str):
    """
    Allows the current user to follow another user.

    Args:
        request: The HTTP request object.
        username (str): The username of the user to follow.

    Returns:
        HttpResponseRedirect: Redirects to the followed user's profile.
    """
    current_user = request.user
    to_user = User.objects.get(username=username)
    to_user_id = to_user
    rel = Relationship(from_user=current_user, to_user=to_user_id)
    rel.save()

    profile_url = reverse('profile', kwargs={'username': username})
    return redirect(profile_url)


@login_required(login_url='login')
def unfollow(request, username: str):
    """
    Allows the current user to unfollow another user.

    Args:
        request: The HTTP request object.
        username (str): The username of the user to unfollow.

    Returns:
        HttpResponseRedirect: Redirects to the unfollowed user's profile.
    """
    current_user = request.user
    to_user = User.objects.get(username=username)
    rel = Relationship.objects.get(from_user=current_user.id, to_user=to_user.id)
    rel.delete()

    profile_url = reverse('profile', kwargs={'username': username})
    return redirect(profile_url)


# ----------------------- Auxiliary functions that are not views ----------------------------
def decrypt_transactions(request: HttpRequest, transactions: QuerySet) -> list:
    """
    Decrypts a queryset of transactions for the given user.

    Args:
        transactions: Queryset of Transaction objects.

    Returns:
        List[Transaction]: A list of decrypted transactions.
    """
    decrypted_transactions = []
    for transaction in transactions:
        if not is_certificate_valid(transaction.user):
            return render(request, 'error.html', {'error': f'Certificado del usuario {transaction.user} no válido'})
        sender_public_key = algorithms.retrieve_public_dh_key(transaction.user)
        dh_private_key = algorithms.retrieve_private_key(transaction.recipient, transaction.recipient.password)
        shared_key = algorithms.get_shared_key(dh_private_key, sender_public_key)

        decrypted_transaction = transaction
        decrypted_transaction.transaction_message = algorithms.decrypt_data(decrypted_transaction.transaction_message, shared_key)
        decrypted_transaction.amount = algorithms.decrypt_data(decrypted_transaction.amount, shared_key)
        decrypted_transactions.append(decrypted_transaction)

    return decrypted_transactions


def verify_all_signatures_and_certificates(request: HttpRequest, transactions: list) -> list:
    """
    Verifies the signatures and certificates for a list of transactions.

    Args:
        request (HttpRequest): The HTTP request object.
        transactions (list): A list of Transaction objects to verify.

    Returns:
        list: A list of verified transactions.
    """
    verified_transactions = []
    for transaction in transactions:
        user = transaction.user

        # Verify the user's certificate
        if not is_certificate_valid(user):
            return render(request, 'error.html', {'error': f'Certificado del usuario {user} no válido'})
        
        # Get the user's public key if the certificate is valid
        user_public_key = get_user_public_key(user)
        if not user_public_key:
            return render(request, 'error.html', {'error': f'Clave pública del usuario {user} no disponible'})
        
        # Verify the transaction signature
        if verify_signature(user_public_key, transaction.signature, transaction.transaction_message, transaction.amount):
            verified_transactions.append(transaction)
    
    return verified_transactions


def process_transaction(request: HttpRequest, transaction_type: str, recipient: str, transaction_message: str, amount: float, user_balance: float) -> str:
    """
    Processes a new transaction posted by the user, using Diffie-Hellman key exchange for encrypting the transaction.

    Args:
        request: HttpRequest object.
        transaction_type (str): Type of the transaction ('enviar_dinero' or 'solicitar_dinero').
        recipient_username (str): Username of the recipient.
        transaction_message (str): Message associated with the transaction.
        amount (float): Amount of money to transact.
        user_balance (float): Current balance of the user.

    Returns:
        str: Result of the transaction processing ('success' or error message).
    """
    if transaction_type == 'enviar_dinero':
        # Check if user has sufficient balance
        if amount > user_balance:
            return 'Saldo insuficiente para realizar la transacción'
        try:
            recipient = User.objects.get(username=recipient)
        except User.DoesNotExist:
            return 'El usuario seleccionado no existe'
        
        # Perform the transaction
        request.user.profile.amount -= amount
        request.user.profile.save()
        recipient.profile.amount += amount
        recipient.profile.save()
    
    elif transaction_type == 'solicitar_dinero':
        # Handle 'solicitar_dinero' transaction type
        try:
            recipient = User.objects.get(username=recipient)
        except User.DoesNotExist:
            return 'El usuario seleccionado no existe'
    
    # Generate shared DH key
    try:
        sender_private_key = algorithms.retrieve_private_key(request.user, request.user.password) 
        if not is_certificate_valid(recipient):
            return render(request, 'error.html', {'error': f'Certificado del usuario {recipient} no válido'})
        recipient_public_key = algorithms.retrieve_public_dh_key(recipient)
        shared_key = algorithms.get_shared_key(sender_private_key, recipient_public_key)
        
    except Exception as e:
        return 'Error al generar la clave compartida'
    
    # Encrypt the transaction message and amount usign the shared_key
    encrypted_message = algorithms.encrypt_data(str(transaction_message), shared_key)
    encrypted_amount = algorithms.encrypt_data(str(amount), shared_key)

    # Sign the transaction
    private_key = decrypt_private_key(settings.MASTER_KEY, get_user_key_path(request.user.id))
    signature = sign_transaction(private_key, transaction_message, amount)

    # Save the transaction
    Transaction.objects.create(
        user=request.user,
        transaction_type=transaction_type,
        recipient=recipient,
        transaction_message=encrypted_message,
        amount=encrypted_amount,
        signature=signature,
    )
    return 'success'