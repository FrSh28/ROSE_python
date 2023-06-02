import threading
import time
import array

if_thread_created = False
counter = 0
num_finished = 0
mtx_counter = threading.Lock()
mtx_bool = threading.Lock()
mtx_test_thread = [threading.Lock() for _ in range(32)]
mtx_update_thread = [threading.Lock() for _ in range(32)]
x = 0
if_test_thread_quit = [False] * 32
if_update_thread_quit = [False] * 32
if_test_thread_run = [False] * 32
if_update_thread_run = [False] * 32
thd_D = None
thd_R = array.array('B', [0] * 64)
thd_L = ""

class ArgTestDel:
    def __init__(self):
        self.updated_D = None
        self.start_pos = 0
        self.end_pos = 0

_arg = [_ for _ in range(64)]

def do_test_deletion(thread_num):
    global counter, thd_D, thd_R, thd_L, mtx_test_thread, if_test_thread_quit, if_test_thread_run, mtx_counter, num_finished
    buf1 = [0] * 32

    while True:
        mtx_test_thread[thread_num].acquire()

        if if_test_thread_quit[thread_num]:
            mtx_test_thread[thread_num].release()
            break

        if if_test_thread_run[thread_num]:
            arg = _arg[thread_num]

            if_test_thread_run[thread_num] = False

            for i in range(arg.start_pos, arg.end_pos):
                if counter == 0:
                    break

                # Hash_G function not provided, implement it accordingly
                Hash_G(buf1, thd_D[i].encode(), thd_R)

                if buf1 == thd_L.encode():
                    counter -= 1

            mtx_counter.acquire()
            num_finished += 1
            mtx_counter.release()

        mtx_test_thread[thread_num].release()
        time.sleep(0.023)


def test_deletion_in_multithread(D, R, L, thread_num):
    global counter, thd_D, thd_R, thd_L, mtx_test_thread, if_test_thread_run, mtx_bool, mtx_test_thread, num_finished
    avg = len(D) // thread_num
    remainder = len(D) % thread_num
    cur_pos = 0

    thd_R = R
    thd_L = L
    thd_D = D

    counter = 1
    num_finished = 0

    for i in range(thread_num):
        arg = _arg[i]

        arg.start_pos = cur_pos
        cur_pos = arg.end_pos = cur_pos + avg
        if remainder > 0:
            arg.end_pos += 1
            remainder -= 1
            cur_pos += 1

        mtx_bool.acquire()
        if_test_thread_run[i] = True
        mtx_bool.release()
        mtx_test_thread[i].release()

    while num_finished < thread_num:
        time.sleep(0.01)

    for i in range(thread_num):
        mtx_test_thread[i].acquire()

    return counter <= 0


def do_update_X_in_multithread(thread_num):
    global thd_D, thd_R, _arg, mtx_update_thread, if_update_thread_quit, if_update_thread_run, mtx_counter, num_finished
    kuprf = KUPRF()
    buf1 = [0] * 48
    str1 = ""

    KUPRF.init()

    while True:
        mtx_update_thread[thread_num].acquire()

        if if_update_thread_quit[thread_num]:
            mtx_update_thread[thread_num].release()
            break

        if if_update_thread_run[thread_num]:
            if_update_thread_run[thread_num] = False

            for i in range(_arg[thread_num].start_pos, _arg[thread_num].end_pos):
                kuprf.update(buf1, thd_R, thd_D[i].encode())
                str1 = buf1[:33]
                _arg[thread_num].updated_D.append(str1)

            mtx_counter.acquire()
            num_finished += 1
            mtx_counter.release()

        mtx_update_thread[thread_num].release()
        time.sleep(0.023)

    KUPRF.clean()


def update_X_in_multithread(D, update_token, thread_num):
    global thd_D, thd_R, _arg, mtx_update_thread, if_update_thread_run, num_finished
    avg = len(D) // thread_num
    remainder = len(D) % thread_num
    cur_pos = 0

    thd_R = update_token
    thd_D = D
    num_finished = 0

    for i in range(thread_num):
        arg = _arg[i]

        arg.start_pos = cur_pos
        cur_pos = arg.end_pos = cur_pos + avg
        arg.updated_D = []
        if remainder > 0:
            arg.end_pos += 1
            remainder -= 1
            cur_pos += 1

        if_update_thread_run[i] = True
        mtx_update_thread[i].release()

    while num_finished < thread_num:
        time.sleep(0.01)

    for i in range(thread_num):
        mtx_update_thread[i].acquire()

    D.clear()
    for i in range(thread_num):
        for itr1 in _arg[i].updated_D:
            D.append(itr1)

        del _arg[i].updated_D

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

    def save(self, L, R, D, C):
        cip = Cipher()

        cip.R = R.encode()
        cip.D = D.encode()
        cip.C = C.encode()

        self._store[L] = cip

        return 0
    def search(self, result, tpd_L, tpd_T, cip_L, cip_R, cip_D, cip_C):
        cip = Cipher()
        buf1, buf2, buf3, buf_Dt, buf_Deltat = bytearray(256), bytearray(256), bytearray(256), bytearray(256), bytearray(256)
        opt = None
        D = []
        is_delta_null = True
        s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp = "", "", "", "", "", ""
        L_cache = set()
        kuprf = KUPRF()

        cip.R = bytearray(cip_R.encode())
        cip.D = bytearray(cip_D.encode())
        cip.C = bytearray(cip_C.encode())

        self._store[cip_L] = cip

        s_Lt = cip_L
        buf_Dt = bytearray(cip_D.encode())
        opt = "op_srh"
        is_delta_null = True

        s_L1 = s_L1t = tpd_L
        s_T1 = s_T1t = tpd_T

        while True:
            L_cache.add(s_L1)
            cip = self._store[s_L1]
            Hash_H(buf2, bytearray(s_T1.encode()), cip.R)

            Xor(bytearray(cip.D.encode()), buf2, buf3)
            if buf3[0] == 0xf0:  # del
                L_cache.remove(s_L1)
                del self._store[s_L1]
                del cip

                s_tmp = buf3[1:34].decode()
                D.append(s_tmp)

                Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
                Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
                Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

                cip = self._store[s_Lt]
                cip.D = buf_Dt.decode()
                s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
            elif buf3[0] == 0x0f:  # add
                for itr in reversed(D):
                    Hash_G(buf1, bytearray(itr.encode()), cip.R)
                    if buf1 == bytearray(s_L1.encode()):
                        L_cache.remove(s_L1)
                        del self._store[s_L1]
                        del cip

                        Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
                        Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
                        Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

                        cip = self._store[s_Lt]
                        cip.D = buf_Dt.decode()
                        s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                        s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                        cip = None
                        break
                if cip is not None:
                    s_Lt = s_L1
                    buf_Dt = cip.D.encode()
                    s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                    opt = "op_add"
                    s_tmp = cip.C.decode()
                    result.append(s_tmp)
            else:
                if opt == "op_srh" and not is_delta_null:
                    L_cache.remove(s_L1)
                    del self._store[s_L1]
                    del cip

                    kuprf.mul(buf1, buf_Deltat, buf3[1:])
                    Xor(buf_Deltat, buf1, buf_Deltat)
                    Xor(buf_Dt[1:], buf_Deltat, buf_Dt[1:])

                    Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
                    Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
                    Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

                    cip = self._store[s_Lt]
                    cip.D = buf_Dt.decode()

                    buf_Deltat = buf1
                    s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                else:
                    s_Lt = s_L1
                    buf_Dt = cip.D.encode()
                    s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                    s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                    opt = "op_srh"
                    buf_Deltat = buf3[1:33]
                    is_delta_null = False
                for itr in D:
                    kuprf.update(buf1, buf3[1:], bytearray(itr.encode()))
                    itr = buf1[:33].decode()

            buf2 = bytearray(64)
            if buf2 == buf3[1 + 33:]:
                break
            s_L1 = buf3[1 + 33:1 + 33 + 32].decode()
            s_T1 = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()

        if not result:
            for l in L_cache:
                cip = self._store[l]
                del cip
                del self._store[l]
        return 0

    def search_with_parallel_del(self, result, tpd_L, tpd_T, cip_L, cip_R, cip_D, cip_C, thread_num):
    x = 0
    cip = Cipher()
    buf1, buf2, buf3, buf_Dt, buf_Deltat = bytearray(256), bytearray(256), bytearray(256), bytearray(256), bytearray(256)
    opt = None
    D = []
    is_delta_null = True
    s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp = "", "", "", "", "", ""
    L_cache = set()
    kuprf = KUPRF()

    cip.R = bytearray(cip_R.encode())
    cip.D = bytearray(cip_D.encode())
    cip.C = bytearray(cip_C.encode())

    self._store[cip_L] = cip

    s_Lt = cip_L
    buf_Dt = bytearray(cip_D.encode())
    opt = OpType.op_srh
    is_delta_null = True

    s_L1 = s_L1t = tpd_L
    s_T1 = s_T1t = tpd_T

    while True:
        L_cache.add(s_L1)
        cip = self._store[s_L1]
        Hash_H(buf2, bytearray(s_T1.encode()), cip.R)

        Xor(bytearray(cip.D.encode()), buf2, buf3)
        if buf3[0] == 0xf0:  # del
            L_cache.remove(s_L1)
            del self._store[s_L1]
            del cip

            s_tmp = buf3[1:34].decode()
            D.append(s_tmp)

            Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
            Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
            Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

            cip = self._store[s_Lt]
            cip.D = buf_Dt.decode()
            s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
            s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
        elif buf3[0] == 0x0f:  # add
            if test_deletion_in_multithread(D, cip.R, s_L1, thread_num):
                L_cache.remove(s_L1)
                del self._store[s_L1]
                del cip

                Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
                Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
                Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

                cip = self._store[s_Lt]
                cip.D = buf_Dt.decode()
                s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                cip = None

            if cip is not None:
                s_Lt = s_L1
                buf_Dt = bytearray(cip.D.encode())
                s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                opt = OpType.op_add
                s_tmp = cip.C.decode()
                result.append(s_tmp)
        else:
            if opt == OpType.op_srh and not is_delta_null:
                L_cache.remove(s_L1)
                del self._store[s_L1]
                del cip

                kuprf.mul(buf1, buf3[1:], buf_Deltat)
                Xor(buf_Deltat, buf1, buf_Deltat)
                Xor(buf_Dt[1:], buf_Deltat, buf_Dt[1:])

                Xor(bytearray(s_L1t.encode()), buf3[1 + 33:], buf2)
                Xor(bytearray(s_T1t.encode()), buf3[1 + 33 + 32:], buf2 + 32)
                Xor(buf_Dt[1 + 33:], buf2, buf_Dt[1 + 33:])

                cip = self._store[s_Lt]
                cip.D = buf_Dt.decode()

                buf_Deltat = buf1
                s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
            else:
                s_Lt = s_L1
                buf_Dt = bytearray(cip.D.encode())
                s_L1t = buf3[1 + 33:1 + 33 + 32].decode()
                s_T1t = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()
                opt = OpType.op_srh
                buf_Deltat = buf3[1:33]
                is_delta_null = False
            update_X_in_multithread(D, buf3[1:], thread_num)

        buf2 = bytearray(64)
        if buf2 == buf3[1 + 33:]:
            break
        s_L1 = buf3[1 + 33:1 + 33 + 32].decode()
        s_T1 = buf3[1 + 33 + 32:1 + 33 + 32 + 32].decode()

    if not result:
        for l in L_cache:
            cip = self._store[l]
            del cip
            del self._store[l]
    return 0


def save_data(self, fname):
    with open(fname, "wb") as f_out:
        size = len(self._store)

        f_out.write(size.to_bytes(8, "little"))
        for key, value in self._store.items():
            save_string(f_out, key)
            f_out.write(bytearray(value.R))
            f_out.write(bytearray(value.D))
            f_out.write(bytearray(value.C))

class RoseServer:
    def load_data(self, fname):
        with open(fname, "rb") as f_in:
            size = int.from_bytes(f_in.read(8), "little")

            for itr in self._store.values():
                del itr
            self._store.clear()

            for i in range(size):
                str1 = self.load_string(f_in)
                cip = Cipher()
                cip.R = f_in.read(16)
                cip.D = f_in.read(1 + 32 * 2 + 33)
                cip.C = f_in.read(CIPHER_SIZE)

                self._store[str1] = cip

    def create_thread(self):
        for i in range(32):
            if_test_thread_quit[i] = False
            if_update_thread_quit[i] = False
            if_test_thread_run[i] = False
            if_update_thread_run[i] = False

            mtx_test_thread[i].lock()
            mtx_update_thread[i].lock()

            t1 = threading.Thread(target=do_test_deletion, args=(i,))
            t2 = threading.Thread(target=do_update_X_in_multithread, args=(i,))

            self.threads.append(t1)
            self.threads.append(t2)
