# coding=utf-8
"""
this is a token generator
"""

import hashlib
import time
import random
import string
import json
import base64
import logging
log = logging.getLogger(__name__)

SECRET_KEY = "gkVxPXtMO76h9HwRJlYGd8miAyu3vbWZOyLvoKxNXnlsCejwU6BP7fSmdJ98Gbr\
              hai2CXAJ3Shr9ZYVLQbzjW0H7dNf8FP4erusHSpmq10oZeXhg9w4tiU5D8fBPxdJF"
class TokenGenerator(object):
    """generater token, verify token, save token"""
    def __init__(self, secret_key=SECRET_KEY):
        self.secret_key = secret_key

    def generater_token(self, username, effective_time=3600, include_dict={}):
        timestamp = self.get_timestamp(effective_time=effective_time)
        try:
            inc_json = json.dumps(include_dict)
        except Exception as ex:
            inc_json = json.dumps({})
        salt_key = self.generater_salt_key(length=64)
        token = self._generater_token(username, timestamp, inc_json,
                                      salt_key, self.secret_key)
        ret = {
                'username': username,
                'token': token,
                'salt_key': salt_key,
                'timestamp': timestamp,
                'include_dict': include_dict,
                }
        jret = json.dumps(ret)
        bret = self.base64_encode(jret)
        return bret

    def _generater_token(self, *args):
        token = hashlib.sha256()
        for value in args:
            token.update(str(value))
        return token.hexdigest()

    def check_token(self, token):
        try:
            jtoken = self.base64_decode(token)
        except Exception as ex:
            log.error("base64 decode error: %s", ex)
            return False
        try:
            dtoken = json.loads(jtoken)
        except Exception as ex:
            log.error("json decode error: %s", ex)
            return False
        now = self.get_timestamp()
        if now > dtoken.get('timestamp', 0):
            return False
        try:
            inc_json = json.dumps(dtoken.get('include_dict', {}))
        except Exception as ex:
            inc_json = json.dumps({})
        ctoken = self._generater_token(dtoken.get('username', ''),
                                       dtoken.get('timestamp', ''),
                                       inc_json,
                                       dtoken.get('salt_key', ''),
                                       self.secret_key)
        if ctoken != dtoken.get('token'):
            return False
        else:
            return True

    def generater_salt_key(self, length=32):
        salt_key = ''
        while length > 32:
            salt_key +=''.join(random.sample(string.ascii_letters+string.digits,
                                             32))
            length -= 32
        salt_key += ''.join(random.sample(string.ascii_letters+string.digits,
                                          32))
        return salt_key

    def get_timestamp(self, effective_time=None):
        timestamp = int(time.time())
        if effective_time:
            timestamp += effective_time
        return timestamp

    def base64_encode(self, input):
        return base64.encodestring(input).strip()

    def base64_decode(self, input):
        return base64.decodestring(input)
