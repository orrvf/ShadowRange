"""Small authenticated wire format for the ShadowRange LAN lab.

HMAC provides integrity and authentication, NOT confidentiality.
"""
import hashlib
import hmac
import json
import secrets


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def mac(key, label, fields):
    return hmac.new(key.encode('utf-8') if isinstance(key, str) else key,
                    (label + '|' + encode(fields)).encode('utf-8'), hashlib.sha256).hexdigest()


def verified(key, label, fields, signature):
    return isinstance(signature, str) and hmac.compare_digest(mac(key, label, fields), signature)


def signed(key, label, fields):
    return {**fields, 'mac': mac(key, label, fields)}


def verify_signed(key, label, packet):
    if not isinstance(packet, dict) or not isinstance(packet.get('mac'), str):
        raise ValueError('missing authentication')
    fields = {k: v for k, v in packet.items() if k != 'mac'}
    if not verified(key, label, fields, packet['mac']):
        raise ValueError('invalid message authentication')
    return fields


def session_key(token, client_nonce, server_nonce):
    return bytes.fromhex(mac(token, 'session', {'client_nonce': client_nonce, 'server_nonce': server_nonce}))


class Channel:
    """Authenticated in-order messages with monotonically increasing sequence numbers."""
    def __init__(self, key, send_label, recv_label):
        self.key, self.send_label, self.recv_label = key, send_label, recv_label
        self.outgoing, self.incoming = 0, 0

    def send(self, fields):
        self.outgoing += 1
        return encode(signed(self.key, self.send_label, {'seq': self.outgoing, **fields}))

    def recv(self, raw):
        packet = json.loads(raw)
        fields = verify_signed(self.key, self.recv_label, packet)
        if type(fields.get('seq')) is not int or fields['seq'] != self.incoming + 1:
            raise ValueError('replayed or out-of-order message')
        self.incoming += 1
        fields.pop('seq')
        return fields


def nonce():
    return secrets.token_hex(16)
