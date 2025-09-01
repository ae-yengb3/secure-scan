from django.contrib.auth.models import AnonymousUser
from channels.middleware import BaseMiddleware
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import User
from urllib.parse import parse_qs

class JWTAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        query_string = scope.get('query_string', b'').decode()
        query_params = parse_qs(query_string)
        token = query_params.get('token', [None])[0]
        
        scope['user'] = AnonymousUser()
        
        if token:
            try:
                access_token = AccessToken(token)
                user_id = access_token['user_id']
                user = await self.get_user(user_id)
                scope['user'] = user
            except (InvalidToken, TokenError, User.DoesNotExist):
                pass
        
        return await super().__call__(scope, receive, send)
    
    async def get_user(self, user_id):
        from channels.db import database_sync_to_async
        return await database_sync_to_async(User.objects.get)(id=user_id)