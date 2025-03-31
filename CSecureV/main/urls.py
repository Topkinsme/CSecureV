from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login',views.login,name='login'),
    path('sign-up',views.sign_up,name='sign_up'),
    path('main-page',views.main_page,name='main_page'),
    path('profile',views.profile,name='profile'),
]
