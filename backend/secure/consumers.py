import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser

class SecureConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if isinstance(self.scope['user'], AnonymousUser):
            await self.close(code=4001)
            return
        
        await self.accept()
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': f'Secure WebSocket connection established for {self.scope["user"].email}'
        }))

    async def disconnect(self, close_code):
        pass
    
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'scan_update':
                await self.handle_scan_update(data)
            else:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': 'Unknown message type'
                }))
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
    
    async def handle_scan_update(self, data):
        # Verify user owns the scan
        scan_id = data.get('scan_id')
        if not scan_id:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'scan_id required'
            }))
            return
        
        from channels.db import database_sync_to_async
        from .models import Scan
        
        try:
            scan = await database_sync_to_async(Scan.objects.get)(
                scan_id=scan_id, user=self.scope['user']
            )
            await self.send(text_data=json.dumps({
                'type': 'scan_update_received',
                'scan_id': scan_id,
                'message': 'Update processed'
            }))
        except Scan.DoesNotExist:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Scan not found or access denied'
            }))