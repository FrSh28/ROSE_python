from enum import IntEnum
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import strxor
from Cryptodome.Hash import HMAC, SHA256, SHA512, SHAKE256, KMAC256
from secp256k1 import Curve


class OP(IntEnum):
    OP_ADD  = 0x0f
    OP_DEL  = 0xf0
    OP_SRCH = 0xff


def gen_rand(bytes = 16) -> int:
    return int.from_bytes(get_random_bytes(bytes), byteorder = 'big')

def gen_key(key_len = 16) -> bytes:
    return get_random_bytes(key_len)

def XOR(left: bytes, right: bytes) -> bytes:
    return strxor.strxor(left, right)


class PRF():
    # 16 bytes key, 32 bytes out
    def __init__(self, out_len = 32) -> None:
        self.out_len = out_len

    def compute(self, key: bytes, keyword: str, id: str, op: OP) -> bytes:
        """
        Compute result
        args:
            key: key for PRF
            keyword: message to compute result
            id: message to compute result
            op: message to compute result
        """
        if self.out_len == 32:
            h = HMAC.new(key = key, digestmod = SHA256)
        elif self.out_len == 64:
            h = HMAC.new(key = key, digestmod = SHA512)
        else:
            h = KMAC256.new(key = key, mac_len = self.out_len)

        h.update(keyword.encode('utf-8'))
        h.update(id.encode('utf-8'))
        h.update(op.to_bytes(1, byteorder = 'big'))

        return h.digest()

class KUPRF(PRF):
    # 32 bytes key, 33 bytes out
    def __init__(self) -> None:
        super().__init__()
        self.curve = Curve()

    def gen_key(self) -> bytes:
        key = ( gen_rand(32) % (self.curve.n - 1) ) + 1
        return key.to_bytes(32, byteorder = 'big')

    def compute(self, key: bytes, keyword: str, id: str, op: OP) -> bytes:
        """
        Compute result
        args:
            key: key for KUPRF
            keyword: message to compute result
            id: message to compute result
            op: message to compute result
        """
        h = SHA256.new()
        h.update(keyword.encode('utf-8'))
        h.update(id.encode('utf-8'))
        h.update(op.to_bytes(1, byteorder = 'big'))

        hash_result = h.digest()
        points = self.curve.mul(self.curve.g, int.from_bytes(hash_result, byteorder = 'big'))
        key = int.from_bytes(key, byteorder = 'big')

        # 33 bytes
        return self.curve.compress(self.curve.mul(points, key))

    def get_update_token(self, key_ori: bytes, key_new: bytes) -> bytes:
        """
        Get key update token
        args:
            key_ori: original key for KUPRF
            key_new: new key for KUPRF
        """
        key_ori = int.from_bytes(key_ori, byteorder = 'big')
        key_new = int.from_bytes(key_new, byteorder = 'big')

        token = (pow(key_ori, -1, self.curve.n) * key_new) % self.curve.n

        return token.to_bytes(33, byteorder = 'big')

    def merge_update_token(self, token_ori: bytes, token_new: bytes) -> bytes:
        """
        Merge key update token
        args:
            token_ori: original token for KUPRF
            token_new: new token for KUPRF
        """
        token_ori = int.from_bytes(token_ori, byteorder = 'big')
        token_new = int.from_bytes(token_new, byteorder = 'big')

        token = (token_ori * token_new) % self.curve.n

        return token.to_bytes(33, byteorder = 'big')

    def update_result(self, msg: bytes, update_token: bytes) -> bytes:
        """
        Compute result
        args:
            mag: original message
            update_token: key update token
        """
        points = self.curve.decompress(msg)
        update_token = int.from_bytes(update_token, byteorder = 'big')


        return self.curve.compress(self.curve.mul(points, update_token))

class HASH():
    def __init__(self, out_len = 32) -> None:
        self.out_len = out_len

    def compute(self, msg: bytes, R: int) -> bytes:
        """
        Compute hash result
        args:
            msg: message to compute hash result
            R: random number
        """
        if self.out_len == 32:
            h = SHA256.new()
        elif self.out_len == 64:
            h = SHA512.new()
        else:
            h = SHAKE256.new()

        h.update(msg)
        h.update(R.to_bytes(16, byteorder = 'big'))

        if self.out_len == 32 or self.out_len == 64:
            return h.digest()
        else:
            return h.read(self.out_len)
