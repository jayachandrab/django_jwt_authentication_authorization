from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import RegisterForm
from django.contrib import messages
from .models import RegisteredUser
from django.core.exceptions import ObjectDoesNotExist
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import UserPassesTestMixin

from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import generate_access_token, generate_refresh_token,decode_token, generate_access_token
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from .permissions import IsAdmin, IsManager, IsAuthenticatedAndHasAnyRole
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.authentication import BaseAuthentication

blacklisted_tokens = set()

def app_homepage(request):
    try:
        if usrnme:
            userdetails = {'username': usrnme}
            return render(request, "loggedin.html", userdetails)
    except NameError:
        return render(request, "homepage.html")


def about_us(request):
    try:
        if usrnme:
            return render(request, "aboutUs.html")
    except NameError:
        return render(request, "aboutUs.html")


def services(request):
    try:
        if usrnme:
            return render(request, "services.html")
    except NameError:
        return render(request, "services.html")


def contact_us(request):
    try:
        if usrnme:
            return render(request, "contactUs.html")
    except NameError:
        return render(request, "contactUs.html")


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Account created successfully")
            return redirect("signin")
    else:
        form = RegisterForm()
        user_info = {'form': form}
        return render(request, "register.html", user_info)


def signin(request):
    global usrnme
    if request.method == 'POST':
        usrnme = request.POST['username']
        psswrd = request.POST['pswd']

        try:
            user = RegisteredUser.objects.get(name=usrnme)
            if usrnme == user.name and psswrd == user.password:
                return redirect("loggedin")
            else:
                messages.info(request, "Incorrect password")
                return redirect("signin")
        except ObjectDoesNotExist:
            messages.info(request, "The user does not exist")
            return redirect("signin")

    else:
        return render(request, "signin.html")


def loggedin(request):
    userdetails = {'username': usrnme}
    return render(request, "loggedin.html", userdetails)


def logout(request):
    global usrnme
    del usrnme
    return render(request, "logout.html")


class UserListView(ListView):
    model = RegisteredUser
    template_name = "user_data.html"
    context_object_name = 'alldata'


class UserDetailView(DetailView):
    model = RegisteredUser


class UserCreateView(CreateView):
    model = RegisteredUser
    form_class = RegisterForm


class UserUpdateView(UserPassesTestMixin, UpdateView):
    model = RegisteredUser
    form_class = RegisterForm

    def test_func(self):
        if self.request.user.is_active:
            return True
        else:
            return False


class UserDeleteView(UserPassesTestMixin, DeleteView):
    model = RegisteredUser
    success_url = '/userlist'

    def test_func(self):
        if self.request.user.is_active:
            print(self.request.user)
            return True
        else:
            return False


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        print(request.data)
        user = authenticate(username=username, password=password)
        if user:
            access_token = generate_access_token(user)
            refresh_token = generate_refresh_token(user)
            return Response({
                'access': access_token,
                'refresh': refresh_token,
            }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class RefreshTokenView(APIView):
    authentication_classes = []  # Override authentication
    permission_classes = []      # Override permissions

    def post(self, request):
        print("Refresh token")
        refresh_token = request.data.get('refresh')

        if refresh_token in blacklisted_tokens:
            return Response({'error': 'This token has been blacklisted'}, status=status.HTTP_401_UNAUTHORIZED)

        payload = decode_token(refresh_token)
        if payload:
            user_id = payload.get('user_id')
            user = User.objects.filter(id=user_id).first()
            if user:
                new_access_token = generate_access_token(user)
                return Response({'access': new_access_token}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


class RefreshTokenView1(APIView):
    authentication_classes = []  # Override authentication
    permission_classes = []      # Override permissions
    
    def post(self, request):
        print("Refresh token")
        refresh_token = request.data.get('refresh')
        payload = decode_token(refresh_token)

        if payload:
            user_id = payload.get('user_id')
            user = User.objects.filter(id=user_id).first()
            if user:
                new_access_token = generate_access_token(user)
                return Response({'access': new_access_token}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)



class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        payload = decode_token(token)
        print("pay load is ",payload)
        if not payload:
            return None

        user = User.objects.filter(id=payload['user_id']).first()
        return (user, None)
    
class ProtectedView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    #permission_classes = [IsAdmin]
    def get(self, request):
        return Response({"message": "You have accessed a protected view!"})


class RegisterView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        role = request.data.get('role', 'assistant')  # Default role is 'assistant'

        # Validate input
        if not username or not password or not email:
            return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

        if role.lower() not in ['admin', 'manager', 'assistant']:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already taken'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

        # Create user
        user = User.objects.create_user(username=username, password=password, email=email, role=role)

        # Generate tokens (optional)
        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        return Response({
            'message': 'User registered successfully',
            'access': access_token,
            'refresh': refresh_token,
        }, status=status.HTTP_201_CREATED)


# View for Admin only
class AdminView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdmin]

    def get(self, request):
        print("in Admin view")
        return Response({"message": "Hello, Admin!"})

# View for Manager only
class ManagerView(APIView):
    permission_classes = [IsManager]

    def get(self, request):
        return Response({"message": "Hello, Manager!"})

# View for all roles (Admin, Manager, Assistant)
class GeneralView(APIView):
    permission_classes = [IsAuthenticatedAndHasAnyRole]

    def get(self, request):
        return Response({"message": "Hello, User with role: {}".format(request.user.role)})


from datetime import datetime

class LogoutView(APIView):
    authentication_classes = []  # Override authentication
    permission_classes = []      # Override permissions

    def post(self, request):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

        payload = decode_token(refresh_token)
        if payload:
            # Blacklist the refresh token
            blacklisted_tokens.add(refresh_token)
            print(f"Token blacklisted at {datetime.now()}")

            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)