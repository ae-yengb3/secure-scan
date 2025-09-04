import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from channels.layers import get_channel_layer

class SecureConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        if isinstance(self.scope['user'], AnonymousUser):
            await self.close(code=4001)
            return
        
        self.user_group = f"user_{self.scope['user'].id}"
        await self.channel_layer.group_add(self.user_group, self.channel_name)
        
        await self.accept()
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': f'Secure WebSocket connection established for {self.scope["user"].email}'
        }))

    async def disconnect(self, close_code):
        if hasattr(self, 'user_group'):
            await self.channel_layer.group_discard(self.user_group, self.channel_name)
    
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'scan_update':
                await self.handle_scan_update(data)
            elif message_type == 'chat_message':
                await self.handle_chat_message(data)
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
    
    async def handle_chat_message(self, data):
        message = data.get('message', '')
        selected_vulnerabilities = data.get('selectedVulnerabilities', [])
        context = data.get('context', '')
        previousMessages = data.get('previousMessages', [])
        
        from channels.db import database_sync_to_async
        from .assistant import get_ai_response
        
        try:
            response = await database_sync_to_async(get_ai_response)(
                message, selected_vulnerabilities, context, previousMessages
            )
            await self.send(text_data=json.dumps({
                'type': 'chat_response',
                'message': response,
                'timestamp': data.get('timestamp')
            }))
        except Exception as e:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': f'AI assistant error: {str(e)}'
            }))
    
    async def scan_progress_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'scan_progress',
            'scan_id': event['scan_id'],
            'progress': event['progress'],
            'remark': event['remark']
        }))