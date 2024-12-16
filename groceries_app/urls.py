from . import views
from django.urls import path, include
from .views import LoginView, RefreshTokenView, ProtectedView,RegisterView,AdminView, ManagerView, GeneralView,LogoutView

urlpatterns = [
    path('', views.app_homepage, name='app_homepage'),
    path('about_us', views.about_us, name="about_us"),
    path('services', views.services, name="services"),
    path('contact_us', views.contact_us, name="contact_us"),
    path('register', views.register, name="register"),
    path('signin', views.signin, name='signin'),
    path('loggedin', views.loggedin, name='loggedin'),
    path('logout', views.logout, name="logout"),
    path('userlist', views.UserListView.as_view(), name='userlist'),
    path('userdetail/<int:pk>/',
         views.UserDetailView.as_view(template_name='user_detail.html'),
         name='userdetail'),
    path('usercreate/',
         views.UserCreateView.as_view(template_name='user_create.html'),
         name='usercreate'),
    path('userupdate/<int:pk>/',
         views.UserUpdateView.as_view(template_name='user_create.html'),
         name='userupdate'),
    path('userdelete/<int:pk>/',
         views.UserDeleteView.as_view(template_name='user_confirm_delete.html'),
         name='userdelete'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('register_user/', RegisterView.as_view(), name='register_user'),
    path('admin_api/', AdminView.as_view(), name='admin_api'),
    path('manager/', ManagerView.as_view(), name='manager_view'),
    path('general/', GeneralView.as_view(), name='general_view'),
        path('logout_api/', LogoutView.as_view(), name='logout_api'),

]
