import os
import cryptography

def RNG(bytes = 16):
    return int.from_bytes(os.urandom(bytes))

class PRF():
    def __init__(self, len_out = 256) -> None:
        pass

    def compute(self, key, keyword, id, op) -> int:
        """
        Compute result
        args:
            key: key for PRF
            keyword: message to compute result
            id: message to compute result
            op: message to compute result
        """
        pass

class KUPRF(PRF):
    def __init__(self, len_out = 256) -> None:
        super().__init__(len_out)

    def compute(self, key, keyword, id, op) -> int:
        """
        Compute result
        args:
            key: key for KUPRF
            keyword: message to compute result
            id: message to compute result
            op: message to compute result
        """
        pass

    def get_update_token(self, key_ori, key_new) -> int:
        """
        Get key update token
        args:
            key_ori: original key for KUPRF
            key_new: new key for KUPRF
        """
        pass

    def merge_update_token(self, token_ori, token_new) -> int:
        """
        Merge key update token
        args:
            token_ori: original token for KUPRF
            token_new: new token for KUPRF
        """
        pass

    def update_result(self, update_token, msg) -> int:
        """
        Compute result
        args:
            update_token: key update token
            mag: original message
        """
        pass

class HASH():
    def __init__(self, len_out = 256) -> None:
        pass

    def compute(self, msg, R):
        """
        Compute hash result
        args:
            msg: message to compute hash result
            R: random number
        """
        pass
