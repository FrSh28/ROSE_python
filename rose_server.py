from utils import OP, PRF, KUPRF, HASH, XOR

class Cipher:
    def __init__(self, R, D, C):
        self.R = self._encode_R(R)
        self.D = self._encode_D(D)
        self.C = self._encode_C(C)
    def _encode_R(self, R):
        return R
    def _encode_D(self, D):
        return D
    def _encode_C(self, C):
        return C
    def get_save_format(self):
        return {'R': self.R, 'D': self.D, 'C': self.C}
    
class RoseServer:
    def __init__(self):
        self._store = {}

        self.kuprf_P = KUPRF()
        self.hash_G = HASH(out_len = 32)
        self.hash_H = HASH(out_len = 1 + 33 + 32 + 32)
        self.op_cnt = 0

    def save(self, query):
        self._save(query['L'], query['R'], query['D'], query['C'])
        self.save_data(f'logs/step_{self.op_cnt}.txt')
        self.op_cnt+=1

    def _save(self, L, R, D, C):
        cip = Cipher(R, D, C)
        self._store[L] = cip

    def search(self, query):
        self._save(query['L'], query['R'], query['D'], query['C'])
        return self._search(tpd_L=query['trapdoor']['srch_L'],
                           tpd_T=query['trapdoor']['srch_T'],
                           cip_L=query['L'])

    def _search(self, tpd_L, tpd_T, cip_L):
        L_cache = set()
        result = []
        del_list = []

        s_Lt = cip_L

        opt = OP.OP_SRCH
        Deltat = None

        s_L1 = s_L1t = tpd_L
        s_T1 = s_T1t = tpd_T

        while s_L1 != bytes(32) or s_T1 != bytes(32):
            L_cache.add(s_L1)
            cip = self._store[s_L1]
            tmp = XOR(cip.D, self.hash_H.compute(s_T1, cip.R))
            s_op1 = tmp[0]
            s_token1 = tmp[1 : 1 + 33]
            s_L11 = tmp[1+33 : 1+33 + 32]
            s_T11 = tmp[1+33+32 : 1+33+32 + 32]

            if s_op1 == OP.OP_DEL:  # del
                L_cache.remove(s_L1)
                del self._store[s_L1]

                del_list.append(s_token1)

                pad = bytes(1+33) + XOR(s_L1t, s_L11) + XOR(s_T1t, s_T11)
                self._store[s_Lt].D = XOR(self._store[s_Lt].D , pad)

                s_L1t = s_L11
                s_T1t = s_T11
            elif s_op1 == OP.OP_ADD:  # add
                for itr in reversed(del_list):
                    del_token = self.hash_G.compute(itr, cip.R)
                    if s_L1 == del_token:
                        L_cache.remove(s_L1)
                        del self._store[s_L1]

                        pad = bytes(1+33) + XOR(s_L1t, s_L11) + XOR(s_T1t, s_T11)
                        self._store[s_Lt].D = XOR(self._store[s_Lt].D , pad)

                        s_L1t = s_L11
                        s_T1t = s_T11
                        cip = None
                        break

                if cip is not None:
                    s_Lt = s_L1
                    s_L1t = s_L11
                    s_T1t = s_T11
                    opt = s_op1
                    result.append(cip.C)
            else:
                if opt == OP.OP_SRCH and Deltat is not None:
                    L_cache.remove(s_L1)
                    del self._store[s_L1]

                    tmp = self.kuprf_P.merge_update_token(Deltat, s_token1)
                    
                    pad = bytes(1) + XOR(Deltat, tmp) + XOR(s_L1t, s_L11) + XOR(s_T1t, s_T11)
                    self._store[s_Lt].D = XOR(self._store[s_Lt].D, pad)

                    s_L1t = s_L11
                    s_T1t = s_T11
                    Deltat = tmp
                else:
                    s_Lt = s_L1
                    s_L1t = s_L11
                    s_T1t = s_T11
                    opt = s_op1
                    Deltat = s_token1

                for i in range(len(del_list)):
                    del_list[i] = self.kuprf_P.update_result(del_list[i], s_token1)

            s_L1 = s_L11
            s_T1 = s_T11

        if not result:
            for l in L_cache:
                del self._store[l]

        return result

    def save_data(self, fname):
        with open(fname, 'w') as f:
            for k, cip in self._store.items():
                f.write(f'L: {k}\n')
                f.write(f'\tR: {cip.R}\n')
                f.write(f'\tD: {cip.D}\n')
                f.write(f'\tC: {cip.C}\n')


if __name__ == "__main__":
    from multiprocessing.connection import Listener
    server = RoseServer()
    address = ('localhost', 6041)     # family is deduced to be 'AF_INET'

    with Listener(address) as listener:
        with listener.accept() as conn:
            while True:
                try:
                    query = conn.recv()
                    if "trapdoor" in query:
                        results = server.search(query)
                        conn.send(results)
                    else:
                        server.save(query)
                except EOFError as e:
                    print("all task are finished, disconnected ")
                    break
