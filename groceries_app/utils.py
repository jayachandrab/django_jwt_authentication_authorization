import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User

def generate_access_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + settings.JWT_SETTINGS['ACCESS_TOKEN_LIFETIME'],
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.JWT_SETTINGS['SECRET_KEY'], algorithm=settings.JWT_SETTINGS['ALGORITHM'])
    return token

def generate_refresh_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + settings.JWT_SETTINGS['REFRESH_TOKEN_LIFETIME'],
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(payload, settings.JWT_SETTINGS['SECRET_KEY'], algorithm=settings.JWT_SETTINGS['ALGORITHM'])
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, settings.JWT_SETTINGS['SECRET_KEY'], algorithms=[settings.JWT_SETTINGS['ALGORITHM']])
        print("====",payload)
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Token is invalid
