from Cryptodome.Util import Padding
from Cryptodome.Cipher import AES
from utils import OP, PRF, KUPRF, HASH, XOR, gen_rand, gen_key


class RoseClient:
    def __init__(self, connection) -> None:
        self.key_sym = gen_key(16)
        self.cipher = SYM_ENC(self.key_sym)

        self.kuprf_P = KUPRF(out_len = 32)
        self.hash_G = HASH(out_len = 32)

        self.prf_F = PRF(out_len = 32)
        self.hash_H = HASH(out_len = 1 + 32 + 32 + 32)

        self.last_key = {}      # { "keyword": {"K": bytes, "S": bytes} }
        self.last_update = {}   # { "keyword": {"op": OP, "id": str, "R": int} }

        self.connection = connection

    def update(self, op: OP, keyword: str, id: str) -> None:
        if keyword in self.last_key:
            keys = self.last_key[keyword]
            K = keys["K"]
            S = keys["S"]
        else:
            K = gen_key(32)
            S = gen_key(16)
            self.last_key[keyword] = {"K": K, "S": S}

        R = gen_rand(16)
        C = self.cipher.encrypt(id)
        L = self.hash_G.compute(self.kuprf_P.compute(K, keyword, id, op), R)

        if keyword in self.last_update:
            last_rec = self.last_update[keyword]
            last_op = last_rec["op"]
            last_id = last_rec["id"]
            last_R  = last_rec["R"]
            last_L = self.hash_G.compute(self.kuprf_P.compute(K, keyword, last_id, last_op), last_R)
            last_T = self.prf_F.compute(S, keyword, last_id, last_op)

            if op == OP.OP_DEL:
                del_token = self.kuprf_P.compute(K, keyword, id, OP.OP_ADD)
            else:
                del_token = bytes(32)

            pad = op.to_bytes(1, byteorder = 'big') + del_token + last_L + last_T
        else:
            pad = op.to_bytes(1, byteorder = 'big') + bytes(32 + 32 + 32)

        hash_result = self.hash_H.compute(self.prf_F.compute(S, keyword, id, op), R)
        D = XOR(hash_result, pad)

        self.last_update[keyword] = {"op": op, "id": id, "R": R}
        load = {"L": L, "R": R, "D": D, "C": C}

        self.connection.send(load)

    def search(self, keyword) -> list:
        if not keyword in self.last_update:
            return None

        keys = self.last_key[keyword]
        last_K = keys["K"]
        last_S = keys["S"]

        K = gen_key(32)
        S = gen_key(16)
        self.last_key[keyword] = {"K": K, "S": S}

        op = OP.OP_SRCH
        R = gen_rand(16)
        C = self.cipher.encrypt(id)

        key_update_token = self.kuprf_P.get_update_token(last_K, K)
        L = self.hash_G.compute(self.kuprf_P.compute(K, keyword, "", op), R)

        last_rec = self.last_update[keyword]
        last_op = last_rec["op"]
        last_id = last_rec["id"]
        last_R  = last_rec["R"]
        last_L = self.hash_G.compute(self.kuprf_P.compute(last_K, keyword, last_id, last_op), last_R)
        last_T = self.prf_F.compute(last_S, keyword, last_id, last_op)
        trapdoor = {"srch_L": last_L, "srch_T": last_T}

        pad = op.to_bytes(1, byteorder = 'big') + key_update_token + last_L + last_T
        hash_result = self.hash_H.compute(self.prf_F.compute(S, keyword, "", op), R)
        D = XOR(hash_result, pad)

        self.last_update[keyword] = {"op": op, "id": "", "R": R}
        
        load = {"L": L, "R": R, "D": D, "C": C, "trapdoor": trapdoor}

        self.connection.send(load)

        search_result = self.connection.recv()
        if search_result:
            id_list = []
            for id_enc in search_result:
                id_list.append(self.cipher.decrypt(id_enc))

            return id_list

        else:
            del self.last_key[keyword]
            del self.last_update[keyword]
            return None
        


class SYM_ENC:
    def __init__(self, key) -> None:
        self.key = key

    def encrypt(self, msg: str) -> dict:
        aes = AES.new(self.key, AES.MODE_GCM)

        data = Padding.pad(msg.encode('utf-8'), 16)
        ciphertext, tag = aes.encrypt_and_digest(data)

        return {"nonce": aes.nonce, "ciphertext": ciphertext, "tag": tag}

    def decrypt(self, cipher: dict) -> str:
        try:
            aes = AES.new(self.key, AES.MODE_GCM, nonce = cipher["nonce"])

            data = aes.decrypt_and_verify(cipher["ciphertext"], received_mac_tag = cipher["tag"]) # TODO
            msg = Padding.unpad(data, 16)

            return msg.decode('utf-8')

        except (ValueError, KeyError):
            print("Incorrect decryption")
            return None

if __name__ == "__main__":
    from multiprocessing.connection import Client

    print("This is the client of ROSE_Python demo...\n")

    address = ('localhost', 6041)     # family is deduced to be 'AF_INET'

    print("Initializing...")
    with Client(address) as conn:
        client = RoseClient(conn)
        print("Complete!")

        while True:
            try:
                op_str = input("Operation(add/del/srch): ")
            except:
                print("End of File.")
                break
            if op_str == "add":
                op = OP.OP_ADD
            elif op_str == "del":
                op = OP.OP_DEL
            elif op_str == "srch":
                op = OP.OP_SRCH
            else:
                continue

            keyword = input("Keyword: ")

            if op == OP.OP_SRCH:
                id_list = client.search(keyword)
                if id_list is None:
                    print("No data available")
                else:
                    for idx, file_id in enumerate(id_list, start = 1):
                        print(f"[{idx:3d}]: {file_id}")
            else:
                id = input("File identifier: ")
                client.update(op, keyword, id)
            
            print("Operation success!\n")
