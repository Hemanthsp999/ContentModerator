from django.urls import path
from django.shortcuts import render
from .views import Register_and_Login, Logout, ModerationSystem, Analytics

register_api = Register_and_Login.as_view({'post': 'userRegister'})
login_api = Register_and_Login.as_view({'post': 'userLogin'})
logout = Logout.as_view({'post': 'userlogout'})
home_api = ModerationSystem.as_view({'post': 'moderationModel'})
analytics_api = Analytics.as_view({'get': 'getAnalytics'})

urlpatterns = [
    path('signup/', lambda request: render(request, 'signin.html')),
    path('login/', lambda request: render(request, 'login.html')),
    path('home/', lambda request: render(request, 'home.html')),  # Home page

    path('api/signup/', register_api, name='api_signup'),
    path('api/login/', login_api, name='api_login'),
    path('api/v1/moderate/text/', home_api, name='api_home'),
    path('api/summary/', analytics_api, name='api_analytics'),
    path('logout/', logout)
]
