# coding = utf-8
"""
The MIT License (MIT)

Copyright (C) 2017 Yongchun Wang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import base64
import json
import time
import hashlib
import logging
import threading
import random
import string
log = logging.getLogger(__name__)
mutex = threading.Lock()

SECRET_KEY = "gkVxPXtMO76h9HwRJlYGd8miAyu3vbWZOyLvoKxNXnlsCejwU6BP7fSmdJ98Gbr\
              hai2CXAJ3Shr9ZYVLQbzjW0H7dNf8FP4erusHSpmq10oZeXhg9w4tiU5D8fBPxdJF"


class SHA256Algorithms(object):
    """
    sha256 algorithms
    """
    def __init__(self):
        self.name = 'SHA256'

    def generator(self, data, secret_key):
        signature = hashlib.sha256()
        signature.update(data)
        signature.update(secret_key)
        return signature.hexdigest()


class SimpleJWT(object):
    """
    simple json web token
    """
    def __init__(self, algorithms=SHA256Algorithms(), options=None):
        self.algorithms = algorithms
        if options is None or not isinstance(options, dict):
            self.options = {}
            self.options['secret_key'] = SECRET_KEY
        else:
            self.options = options

    def _get_header(self):
        header = {
        'typ': 'JWT',
        'alg': self.algorithms.name,
        }
        return header

    def _generater_body(self, payload):
        header = self._get_header()
        header_json = self.json_dumps(header)
        header_base64 = self.base64_encode(header_json)
        payload_json = self.json_dumps(payload)
        payload_base64 = self.base64_encode(payload_json)
        body = '.'.join([header_base64, payload_base64])
        return body

    def _generater_signature(self, body, secret_key=None):
        if secret_key is None and 'secret_key' not in self.options:
            raise Exception("Secret key not set!")
        secret_key = self.options['secret_key'] if 'secret_key' in self.options else secret_key
        return self.algorithms.generator(body, secret_key)

    def get_default_payload(self):
        payload = {
            'timestamp': int(time.time()),
            'id': self.get_token_id(),
            'saltkey': self.generater_salt_key(128)
        }
        return payload

    def generater_token(self, payload, valid_period=3600):
        default_payload = self.get_default_payload()
        if not isinstance(payload, dict):
            raise Exception("payload expected a dict")
        default_payload.update(payload)
        default_payload['valid_period'] = int(valid_period)
        body = self._generater_body(default_payload)
        signature = self._generater_signature(body)
        signature_base64 = self.base64_encode(signature)
        token = '.'.join([body, signature_base64])
        return token

    def validate_token(self, token):
        params = token.split('.')
        header_json = self.base64_decode(params[0])
        header = self.json_loads(header_json)
        if header != self._get_header():
            return False
        payload_json = self.base64_decode(params[1])
        payload = self.json_loads(payload_json)
        if 'timestamp' not in payload or 'id' not in payload or 'valid_period' not in payload:
            return False
        if self.is_outtime(payload):
            return False
        signature = self.base64_decode(params[2])
        body = self._generater_body(payload)
        gsignature = self._generater_signature(body)
        if signature != gsignature:
            return False
        return True

    def is_outtime(self, payload):
        try:
            timestamp = int(payload.get('timestamp'))
            valid_period = int(payload.get('valid_period'))
            if timestamp +  valid_period < int(time.time()):
                return True
            else:
                return False
        except Exception as ex:
            log.error("run is_outtime error: %s", ex)
            return True

    def json_dumps(self, data):
        try:
            ret = json.dumps(data)
        except Exception as ex:
            log.error("json dumps error: %s", ex)
            ret = json.dumps("{}")
        return ret

    def json_loads(self, data):
        try:
            ret = json.loads(data)
        except Exception as ex:
            log.error("json loads error: %s", ex)
            ret = {}
        return ret

    def base64_encode(self, data):
        try:
            ret = base64.urlsafe_b64encode(data)
        except Exception as ex:
            log.error("base64 encode error: %s", ex)
            ret = ""
        return ret

    def base64_decode(self, data):
        try:
            ret = base64.urlsafe_b64decode(data)
        except Exception as ex:
            log.error("base64 decode error: %s", ex)
            ret = ""
        return ret

    def generater_salt_key(self, length=32):
        salt_key = ''
        while length > 32:
            salt_key +=''.join(random.sample(string.ascii_letters+string.digits,
                                             32))
            length -= 32
        salt_key += ''.join(random.sample(string.ascii_letters+string.digits,
                                          32))
        return salt_key

    def get_token_id(self):
        mutex.acquire()
        if 'id' not in self.options:
            self.options['id'] = 0
        self.options['id'] += 1
        ret = self.options['id']
        mutex.release()
        return ret
