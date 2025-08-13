# ContentModerator

# Achieved:

    1. Backend with Django
    2. RESTful API
    3. LLM Integration (Classification)
    4. Third-party Integration: Slack
    5. Docker Configuration
    6. API Endpoints ( Except "**/image**" )
    7. Database

# Not Achieved:

    1. Image Endpoint
    2. Sentry Integration
    3. Celery

# Routes:

Frontend api:

    Login: http://127.0.0.1:8000/
    Signin: http://127.0.0.1:8000/handler/signin/
    Home: http://127.0.0.1:8000/handler/home/

Backend api (Test with Postman):

    Signin: http://127.0.0.1:8000/handler/api/signup/
    Login: http://127.0.0.1:8000/handler/api/login/
    Text: http://127.0.0.1:8000/handler/api/v1/moderate/text/
    Summary: http://127.0.0.1:8000/handler/api/summary/
    Logout: http://127.0.0.1:8000/handler/logout/

# How to install & run ?

1. Clone the repo

```bash
git clone "repo"
```

2. Build docker image

```bash
sudo docker-compose build
```

3. start application

```bash
sudo docker-compose up
```

4. Run database migrations to create SQLite

```bash
sudo docker-compose run web python manage.py migrate

```

5. Open the application

```bash
http://localhost:8000/home/
```

6. Stop Application

```bash
sudo docker-compose down
```
