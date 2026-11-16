"""Single-operator access boundary for HTTP and WebSocket requests."""
import base64
import hashlib
import hmac
import ipaddress
from urllib.parse import urlsplit
from starlette.responses import JSONResponse
from config import Config


class AccessControlMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] not in ('http', 'websocket'):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get('headers', [])}
        try:
            host = urlsplit('//' + headers.get('host', '')).hostname
        except ValueError:
            host = None
        reason, status = None, 403
        if host not in Config.ALLOWED_HOSTS:
            reason = 'Host is not allowed'
        elif Config.ADMIN_PASSWORD:
            try:
                scheme, token = headers.get('authorization', '').split(' ', 1)
                user, password = base64.b64decode(token, validate=True).decode().split(':', 1)
                valid = scheme.lower() == 'basic' and hmac.compare_digest(
                    hashlib.sha256((user + ':' + password).encode()).digest(),
                    hashlib.sha256((Config.ADMIN_USER + ':' + Config.ADMIN_PASSWORD).encode()).digest())
            except (ValueError, UnicodeError):
                valid = False
            if not valid:
                reason, status = 'Authentication required', 401
        else:
            try:
                local = ipaddress.ip_address(scope.get('client', ('', 0))[0]).is_loopback
            except ValueError:
                local = False
            if not local:
                reason = 'Remote access requires IMAGEGUARD_ADMIN_PASSWORD'
        origin = headers.get('origin')
        if origin:
            try:
                expected_scheme = {'ws': 'http', 'wss': 'https'}.get(scope['scheme'], scope['scheme'])
                parsed_origin = urlsplit(origin)
                same_origin = parsed_origin.netloc == headers.get('host') and parsed_origin.scheme == expected_scheme
            except ValueError:
                same_origin = False
            if not same_origin:
                reason, status = 'Cross-origin requests are not allowed', 403
        if headers.get('sec-fetch-site') == 'cross-site':
            reason, status = 'Cross-site requests are not allowed', 403
        if scope['type'] == 'http':
            try:
                if int(headers.get('content-length', '0')) > Config.MAX_CONTENT_LENGTH + 1024 * 1024:
                    reason, status = 'Request body exceeds upload limit', 413
            except ValueError:
                reason, status = 'Invalid Content-Length', 400
        if reason:
            if scope['type'] == 'websocket':
                return await send({'type': 'websocket.close', 'code': 1008})
            response = JSONResponse({'detail': reason}, status_code=status,
                                    headers={'WWW-Authenticate': 'Basic realm="ImageGuard", charset="UTF-8"'} if status == 401 else {})
            return await response(scope, receive, send)
        async def secure_send(message):
            if message['type'] == 'http.response.start':
                message.setdefault('headers', []).extend([
                    (b'x-content-type-options', b'nosniff'), (b'x-frame-options', b'DENY'),
                    (b'referrer-policy', b'no-referrer'), (b'cache-control', b'no-store'),
                    (b'content-security-policy', b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")])
            await send(message)
        if scope['type'] == 'http' and scope.get('method') in ('POST', 'PUT', 'PATCH'):
            # Bound chunked requests too, before multipart parsing can spool an
            # unbounded body to disk. The complete request cap includes fields.
            messages, total = [], 0
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                total += len(message.get('body', b''))
                if total > Config.MAX_CONTENT_LENGTH + 1024 * 1024:
                    return await JSONResponse({'detail': 'Request body exceeds upload limit'}, status_code=413)(scope, receive, secure_send)
                messages.append(message)
                if not message.get('more_body', False):
                    break
            async def replay():
                return messages.pop(0) if messages else await receive()
            return await self.app(scope, replay, secure_send)
        await self.app(scope, receive, secure_send)
