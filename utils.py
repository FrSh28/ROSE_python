from telnetlib import TN3270E
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import number, strxor
from Cryptodome.Hash import HMAC, SHA256, SHA512, SHAKE256, KMAC256

# number.getPrime(8 * out_len)
MODULUS = 25877549389260330581249947051848916310864513794016566320407061879535978927442699

def RNG(bytes = 16):
    return int.from_bytes(gen_key(bytes))

def gen_key(key_len = 16) -> bytes:
    return get_random_bytes(key_len)

class PRF():
    # 16 bytes key, 32 bytes out
    def __init__(self, out_len) -> None:
        self.out_len = out_len

    def compute(self, key: bytes, keyword: str, id: str, op: str) -> bytes:
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
        h.update(op.encode('utf-8'))

        return h.digest()

class KUPRF(PRF):
    # 32 bytes key, 33 bytes out
    def __init__(self, out_len = 33) -> None:
        super().__init__()
        self.out_len = out_len
        self.modulus = MODULUS      # number.getPrime(8 * out_len)

    def get_modulus(self) -> int:
        return self.modulus

    def set_modulus(self, modulus) -> int:
        if modulus >> (8 * self.out_len - 1):
            self.modulus = modulus
        else:
            raise ValueError(f"modulus cannot be shorter than ourput length ({self.out_len*8} bits)")

    def compute(self, key: bytes, keyword: str, id: str, op: str) -> bytes:
        """
        Compute result
        args:
            key: key for KUPRF
            keyword: message to compute result
            id: message to compute result
            op: message to compute result
        """
        h = SHAKE256.new()
        h.update(keyword.encode('utf-8'))
        h.update(id.encode('utf-8'))
        h.update(op.encode('utf-8'))
        
        base = int.from_bytes(h.digest())
        exp  = int.from_bytes(key)

        return pow(base, exp, self.modulus).to_bytes()

    def get_update_token(self, key_ori: bytes, key_new: bytes) -> bytes:
        """
        Get key update token
        args:
            key_ori: original key for KUPRF
            key_new: new key for KUPRF
        """
        key_ori = int.from_bytes(key_ori)
        key_new = int.from_bytes(key_new)

        token = (pow(key_ori, -1, self.modulus) * key_new) % self.modulus

        return token.to_bytes()

    def merge_update_token(self, token_ori: bytes, token_new: bytes) -> bytes:
        """
        Merge key update token
        args:
            token_ori: original token for KUPRF
            token_new: new token for KUPRF
        """
        token_ori = int.from_bytes(token_ori)
        token_new = int.from_bytes(token_new)

        token = (token_ori * token_new) % self.modulus

        return token.to_bytes()

    def update_result(self, msg: bytes, update_token: bytes) -> int:
        """
        Compute result
        args:
            mag: original message
            update_token: key update token
        """
        msg = int.from_bytes(msg)
        update_token = int.from_bytes(update_token)

        return pow(msg, update_token, self.modulus).to_bytes()

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
            h = SHAKE256.new(mac_len = self.out_len)

        h.update(msg)
        h.update(R.to_bytes())

        return h.digest()


def XOR(left: bytes, right: bytes) -> bytes:
    return strxor.strxor(left, right)
