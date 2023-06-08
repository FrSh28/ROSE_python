import threading
import time
import array
from utils import PRF, KUPRF, HASH, XOR
CIPHER_SIZE = 32

class Cipher:
    def __init__(self, R, D, C):
        self.R = self._encode_R(R)
        self.D = self._encode_D(D)
        self.C = self._encode_C(C)
    def _encode_R(self, R):
        return R
    def _encode_D(self, D):
        return bytearray(D[:1 + 33 + 32 * 2])
    def _encode_C(self, C):
        return C
    def get_save_format(self):
        return {'R': self.R, 'D': self.D, 'C': self.C}
    
class RoseServer:
    def __init__(self, enable_thread=False):
        self.if_thread_created = False
        if enable_thread:
            if not self.if_thread_created:
                self._create_thread()
                self.if_thread_created = True
        else:
            self.if_thread_created = False

        self._store = {}

        self.kuprf_P = KUPRF()
        self.hash_G = HASH(out_len = 32)
        self.hash_H = HASH(out_len = 1 + 33 + 32*2)

    def _create_thread(self):
        pass

    def __del__(self):
        for cip in self._store.values():
            del cip
        self._store.clear()

        if self.if_thread_created:
            for i in range(32):
                if_test_thread_quit[i] = True
                if_update_thread_quit[i] = True

            for t in self.threads:
                t.join()

        self.if_thread_created = False
    def setup(self):
        for cip in self._store.values():
            del cip
        self._store.clear()
        return 0

    def save(self, query):
        self._save(query['L'], query['R'], query['D'], query['C'])
        self._save_to_json()
    def _save_to_json(self):
        tmp = {}
        for k, cip in self._store.items():
            tmp[k] = cip.get_save_format()
        # print(tmp)
        # with open('db.json', 'w') as f:
        #     json.dump(tmp, f, indent=4)
    def _save(self, L, R, D, C):
        cip = Cipher(R, D, C)
        self._store[L] = cip
        return 0

    def search(self, query):
        return self._search(tpd_L=query['trapdoor']['srch_L'],
                           tpd_T=query['trapdoor']['srch_T'],
                           cip_L=query['L'],
                           cip_R=query['R'],
                           cip_D=query['D'],
                           cip_C=query['C'])
    def _search(self, tpd_L, tpd_T, cip_L, cip_R, cip_D, cip_C):
        result = []
        cip = Cipher(cip_R, cip_D, cip_C)
        buf1, buf2, buf3, buf_Dt, buf_Deltat = bytearray(256), bytearray(256), bytearray(256), bytearray(256), bytearray(256)
        opt = None
        D = []
        is_delta_null = True
        s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp = "", "", "", "", "", ""
        L_cache = set()

        self._store[cip_L] = cip

        s_Lt = cip_L
        buf_Dt[:len(cip.D)] = cip.D
        opt = "op_srh"
        is_delta_null = True
        s_L1 = s_L1t = tpd_L
        s_T1 = s_T1t = tpd_T
        cnt = 0
        while True:
            L_cache.add(s_L1)
            cip = self._store[s_L1]
            buf2[:1 + 32 * 2 + 33] = self.hash_H.compute(s_T1, cip.R)
            buf3[:1 + 33 + 32 * 2] = XOR(cip.D[:1 + 33 + 32 * 2], buf2[:1 + 33 + 32 * 2])
            if buf3[0] == 0xf0:  # del
                print('del branch')
                L_cache.remove(s_L1)
                del self._store[s_L1]
                del cip

                s_tmp = buf3[1:34]
                D.append(s_tmp)

                buf2[:32] = XOR(s_L1t[:32], buf3[1 + 33: 1 + 33 + 32])
                
                buf2[32: 32+32] = XOR(s_T1t[:32], buf3[1 + 33 + 32: 1 + 33 + 32 + 32])
                buf_Dt[1+33:1+33+64] = XOR(buf_Dt[1 + 33: 1 + 33 + 64], buf2[:64])

                cip = self._store[s_Lt]
                cip.D[:1 + 32 * 2 + 33] = buf_Dt[:1 + 32 * 2 + 33]
                
                s_L1t = buf3[1 + 33:1 + 33 + 32]
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32]
            elif buf3[0] == 0x0f:  # add
                print('add branch')
                for itr in reversed(D):
                    buf1[:32] = self.hash_G.compute(itr, cip.R)
                    print(len(buf1), buf1)
                    print(len(s_L1), s_L1)
                    if buf1[:32] == s_L1[:32]:
                        L_cache.remove(s_L1)
                        del self._store[s_L1]
                        del cip

                        buf2[:32] = XOR(s_L1t, buf3[1 + 33: 1 + 33 + 32])
                        buf2[32: 32 + 32] = XOR(s_T1t, buf3[1 + 33 + 32: 1 + 33 + 32 + 32])
                        buf_Dt[1 + 33: 1 + 33 + 64] = XOR(buf_Dt[1 + 33: 1 + 33 + 64], buf2[:64])

                        cip = self._store[s_Lt]
                        cip.D = buf_Dt
                        s_L1t = buf3[1 + 33:1 + 33 + 32]
                        s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32]
                        cip = None
                        break
                if cip is not None:
                    s_Lt = s_L1
                    buf_Dt[:len(cip.D)] = cip.D
                    # s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                    # s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                    s_L1t = buf3[1 + 33:1 + 33 + 32]
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32]
                    opt = "op_add"
                    s_tmp = cip.C
                    result.append(s_tmp)
            else:
                print('srch branch')
                if opt == "op_srh" and not is_delta_null:
                    L_cache.remove(s_L1)
                    del self._store[s_L1]
                    del cip

                    tmp = self.kuprf_P.merge_update_token(buf_Deltat, buf3[1:])
                    buf1[:len(tmp)] = tmp
                    
                    buf_Deltat[:32] = XOR(buf_Deltat[:32], buf1[:32])
                    
                    buf_Dt[1: 1+32] = XOR(buf_Dt[1:1+32], buf_Deltat[:32])
                    buf2[:32] = XOR(s_L1t, buf3[1 + 33:1 + 33 +32])
                    buf2[32:32+32] = XOR(s_T1t, buf3[1 + 33 + 32: (1 + 33 + 32) + 32])
                    buf_Dt[1 + 33: 1 + 33 + 64] = XOR(buf_Dt[1 + 33: 1 + 33 + 64], buf2[:64])

                    cip = self._store[s_Lt]
                    cip.D = buf_Dt

                    buf_Deltat[:32] = buf1[:32]
                    s_L1t = buf3[1 + 33:1 + 33 + 32]
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32]
                else:
                    s_Lt = s_L1
                    buf_Dt[:len(cip.D)] = cip.D
                    s_L1t = buf3[1 + 33:1 + 33 + 32]
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32]
                    opt = "op_srh"
                    buf_Deltat[:32] = buf3[1: 1+32]
                    is_delta_null = False
                for itr in D:
                    buf1 = self.kuprf_P.update_result(buf3[1:], itr)
                    itr = buf1[:33]

            buf2[:64] = bytearray(64)
            if buf2[:64] == buf3[1 + 33: 1 + 33 + 64]:
                break
            s_L1 = bytes(buf3[1 + 33:1 + 33 + 32])
            s_T1 = buf3[1 + 33 + 32:1 + 33 + 32 + 32]

        if not result:
            for l in L_cache:
                cip = self._store[l]
                del cip
                del self._store[l]
        return result

    def save_data(self, fname):
        with open(fname, "wb") as f_out:
            size = len(self._store)

            f_out.write(size.to_bytes(8, "little"))
            for key, value in self._store.items():
                save_string(f_out, key)
                f_out.write(value.R)
                f_out.write(value.D)
                f_out.write(value.C)

if __name__ == "__main__":
    from multiprocessing.connection import Listener
    from array import array
    server = RoseServer()
    server.setup()
    address = ('localhost', 6041)     # family is deduced to be 'AF_INET'

    with Listener(address) as listener:
        with listener.accept() as conn:
            while True:
                query = conn.recv()
                if "trapdoor" in query:
                    results = server.search(query)
                    conn.send(results)
                else:
                    server.save(query)