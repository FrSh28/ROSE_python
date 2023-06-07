from typing import List, Dict, Set
from rose_client import RoseClient
from rose_server import RoseServer

class SSEBenchmark:
    def __init__(self):
        self.data_to_encrypt = {}
        self.total_add_records = 0
        self.keyword_number = 0
    
    def Setup(self, filename):
        L = ""
        R = ""
        D = ""
        C = ""
        word = ""
        name = 0
        f_data = open(filename, "r")
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        counter = 0
        # fp_clnt = open("rose_client_data.dat", "rb")
        # fp_srv = open("rose_server_data.dat", "rb")

        self.data_to_encrypt.clear()
        self.total_add_records = 0

        self.keyword_number = int(f_data.readline())
        for i in range(self.keyword_number):
            word = f_data.readline().rstrip()
            if word not in self.data_to_encrypt:
                self.data_to_encrypt[word] = []

            _v = self.data_to_encrypt[word]

            file_numbers = int(f_data.readline())
            for j in range(file_numbers):
                self.total_add_records += 1
                name = int(f_data.readline().replace('\n', ''), 16)
                _v.append(name)
        f_data.close()

        print("read", self.total_add_records, "save records")
        print()

        # if fp_clnt and fp_srv:
        #     fp_clnt.close()
        #     fp_srv.close()
        # else:
        #     rose_clnt.setup()
        #     rose_srv.setup()
        #     for a in self.data_to_encrypt:
        #         for f_name in self.data_to_encrypt[a]:
        #             rose_clnt.encrypt(L, R, D, C, op_add, a, f_name)
        #             rose_srv.save(L, R, D, C)
        #     rose_clnt.save_data()
        #     rose_srv.save_data()

        return 1

    def benchmark_gen_add_cipher(self):
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        L = ""
        R = ""
        D = ""
        C = ""
        _add_number = 0

        rose_clnt.setup()
        rose_srv.setup()

        start = time.time()
        for a in self.data_to_encrypt:
            for f_name in self.data_to_encrypt[a]:
                rose_clnt.encrypt(L, R, D, C, op_add, a, f_name)
                rose_srv.save(L, R, D, C)
                _add_number += 1
        end = time.time()
        elapsed = end - start
        print("encryption time cost:")
        print("\ttotally", _add_number, "records, total", elapsed * 1000000, "us")
        print("\taverage time", (elapsed * 1000000) / _add_number, "us")
        print("length of a ciphertext is", 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE, "bytes")
        print()

        return 1
    def benchmark_gen_del_cipher(self):
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        L = ""
        R = ""
        D = ""
        C = ""
        _del_number = 0

        rose_clnt.setup()
        rose_srv.setup()
        rose_clnt.load_data()
        rose_srv.load_data()

        start = time.time()
        for a in self.data_to_encrypt:
            for f_name in self.data_to_encrypt[a]:
                rose_clnt.encrypt(L, R, D, C, op_del, a, f_name)
                rose_srv.save(L, R, D, C)
                _del_number += 1
        end = time.time()
        elapsed = end - start

        print("generating delete ciphertexts time cost:")
        print("\ttotal", _del_number, "time cost:", elapsed * 1000000, "us")
        print("\taverage", (elapsed * 1000000) / _del_number, "us")
        print()
        print("length of a deleting ciphertext is", 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE, "bytes")
        print()

        return 1

    def benchmark_search(self):
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        cipher_out = []
        labels = []
        plain_out = []
        total_time_in_srch = 0
        clnt_time_cost_in_srch = 0
        srv_time_cost_in_srch = 0
        total_data_size = 0
        tpd_L = ""
        tpd_T = ""
        L = ""
        R = ""
        D = ""
        C = ""
        for itr in self.data_to_encrypt:
            rose_clnt.setup()
            rose_srv.setup()

            rose_clnt.load_data()
            rose_srv.load_data()

            cipher_out = []
            plain_out = []
            labels = []

            cipher_out.reserve(300000)
            plain_out.reserve(300000)
            labels.reserve(300000)

            start = time.time()
            rose_clnt.trapdoor(itr, tpd_L, tpd_T, L, R, D, C)
            end = time.time()
            elapsed = end - start
            clnt_time_cost_in_srch = elapsed * 1000000
            total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE

            start = time.time()
            rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C)
            end = time.time()
            elapsed = end - start
            srv_time_cost_in_srch = elapsed * 1000000
            total_data_size += len(cipher_out) * CIPHER_SIZE

            start = time.time()
            rose_clnt.decrypt(plain_out, itr, cipher_out)
            end = time.time()
            elapsed = end - start
            clnt_time_cost_in_srch += elapsed * 1000000
            total_data_size += len(plain_out) * sys.getsizeof(int)

            total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch

            print("Searching for keyword:", itr)
            print("\tTotally find", len(plain_out), "records and the last file ID is", plain_out[-1])
            print("\tTime cost of client is", clnt_time_cost_in_srch, "us, average is",
                  clnt_time_cost_in_srch / len(plain_out))
            print("\tTime cost of server is", srv_time_cost_in_srch, "us, average is",
                  srv_time_cost_in_srch / len(plain_out))
            print("\tTime cost of the whole search phase is", total_time_in_srch, "us")
            print("\tAverage time cost is", total_time_in_srch / len(plain_out), "us")
            print("\tTotal data exchanged are", total_data_size, "Bytes,", total_data_size / 1024, "KB,",
                  total_data_size / 1024 / 1024, "MB")
            print()

        return 0
    def benchmark_deletions(self):
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        cipher_out = []
        labels = []
        plain_out = []
        portion_to_del = [0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5]
        srch_count = [0, 20, 50, 70, 100, 120, 150, 170, 200]
        total_time_in_srch = 0
        clnt_time_cost_in_srch = 0
        srv_time_cost_in_srch = 0
        total_data_size = 0
        keyword_to_delete = "40"
        tpd_T = ""
        tpd_L = ""
        L = ""
        R = ""
        D = ""
        C = ""
        counter = 0
        indices = set()

        print("\nBegin test deletions\n")
        for number_of_srch in srch_count:
            for por in portion_to_del:
                rose_clnt.setup()
                rose_srv.setup()
                rose_clnt.load_data()
                rose_srv.load_data()

                fnames = self.data_to_encrypt[keyword_to_delete]

                cipher_out.clear()
                plain_out.clear()
                labels.clear()
                indices.clear()

                cipher_out = [None] * 300000
                plain_out = [None] * 300000
                labels = [None] * 300000

                for i in range(number_of_srch):
                    rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C)
                    rose_srv.save(L, R, D, C)

                self.randomly_select_deletions(indices, keyword_to_delete, por)
                for itr in indices:
                    rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, fnames[itr])
                    rose_srv.save(L, R, D, C)

                start = time.time()
                rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C)
                end = time.time()
                elapsed = end - start
                clnt_time_cost_in_srch = elapsed * 1000000
                total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE

                start = time.time()
                rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C)
                end = time.time()
                elapsed = end - start
                srv_time_cost_in_srch = elapsed * 1000000
                total_data_size += len(cipher_out) * CIPHER_SIZE

                start = time.time()
                rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out)
                end = time.time()
                elapsed = end - start
                clnt_time_cost_in_srch += elapsed * 1000000
                total_data_size += len(plain_out) * 4

                total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch

                print("Searching for keyword:", keyword_to_delete)
                print("Number of Search Queries:", number_of_srch)
                print("Deletion Portion:", por, "and deleted entries is:", int(por * len(fnames)))
                print("\tTotally find", len(plain_out))
                print("\tTime cost of client is", clnt_time_cost_in_srch, "us, average is",
                      clnt_time_cost_in_srch / len(plain_out))
                print("\tTime cost of server is", srv_time_cost_in_srch, "us, average is",
                      srv_time_cost_in_srch / len(plain_out))
                print("\tTime cost of the whole search phase is", total_time_in_srch, "us")
                print("\tAverage time cost is", total_time_in_srch / len(plain_out), "us")
                print("\tTotal data exchanged are", total_data_size, "Bytes\n")

        return 0

    def randomly_select_deletions(self, indices, keyword, por):
        t = self.data_to_encrypt[keyword]
        total_number_filenames = len(t)
        required_number = int(por * total_number_filenames)
        cur_number = 0
        index = 0

        if required_number >= total_number_filenames:
            required_number = total_number_filenames
            for i in range(total_number_filenames):
                indices.add(i)
        else:
            while cur_number < required_number:
                index = random.randint(0, total_number_filenames - 1)
                if index not in indices:
                    indices.add(index)
                    cur_number += 1

    def benchmark_deletion_in_parallel():
        print("\n\nBegin test parallel deletions")

        rose_clnt = RoseClient()
        rose_srv = RoseServer(True)
        cipher_out = []
        labels = []
        plain_out = []
        portion_to_del = [0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5]
        srch_count = [0, 20, 50, 70, 100, 120, 150, 170, 200]
        total_time_in_srch = 0
        clnt_time_cost_in_srch = 0
        srv_time_cost_in_srch = 0
        total_data_size = 0
        keyword_to_delete = "40"
        tpd_T = ""
        tpd_L = ""
        L = ""
        R = ""
        D = ""
        C = ""
        counter = 0
        indices = set()
        fnames = data_to_encrypt[keyword_to_delete]

        for sc in srch_count:
            for por in portion_to_del:
                rose_clnt.setup()
                rose_srv.setup()

                rose_clnt.load_data()
                rose_srv.load_data()

                indices.clear()

                # Store data at first
                for i in range(sc):
                    rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C)
                    rose_srv.save(L, R, D, C)

                # Generate delete ciphertexts
                randomly_select_deletions(indices, keyword_to_delete, por)
                for itr in indices:
                    rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, fnames[itr])
                    rose_srv.save(L, R, D, C)

                rose_clnt.save_data("rose_clnt_paral_data.dat")
                rose_srv.save_data("rose_srv_paral_data.dat")

                for num_thread in range(2, 17, 2):
                    print("search count:", sc, ", portion:", por, ", number of thread:", num_thread)

                    rose_clnt.setup()
                    rose_srv.setup()

                    rose_clnt.load_data("rose_clnt_paral_data.dat")
                    rose_srv.load_data("rose_srv_paral_data.dat")

                    cipher_out.clear()
                    plain_out.clear()
                    labels.clear()

                    cipher_out.reserve(300000)
                    plain_out.reserve(300000)
                    labels.reserve(300000)

                    # Search stage 1: generate trapdoor
                    start = datetime.datetime.now()
                    rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C)
                    end = datetime.datetime.now()
                    elapsed = (end - start).microseconds
                    clnt_time_cost_in_srch = elapsed
                    total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE

                    # Search stage 2: find ciphertexts
                    if num_thread == 1:
                        start = datetime.datetime.now()
                        # rose_srv.search_with_parallel_del(cipher_out, tpd_L, tpd_T, L, R, D, C, num_thread)
                        rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C)
                        end = datetime.datetime.now()
                    else:
                        start = datetime.datetime.now()
                        rose_srv.search_with_parallel_del(cipher_out, tpd_L, tpd_T, L, R, D, C, num_thread)
                        end = datetime.datetime.now()

                    elapsed = (end - start).microseconds
                    srv_time_cost_in_srch = elapsed
                    total_data_size += len(cipher_out) * CIPHER_SIZE

                    # Search stage 3: decrypt and re-encrypt ciphertexts
                    start = datetime.datetime.now()
                    rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out)
                    end = datetime.datetime.now()
                    elapsed = (end - start).microseconds
                    clnt_time_cost_in_srch += elapsed
                    total_data_size += len(plain_out) * sizeof(int)

                    total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch

                    print("Searching for keyword:", keyword_to_delete)
                    print("Deletion Portion:", por, "and deleted entries is:", int(por * len(fnames)))
                    print("Number of Search Queries:", sc)
                    print("Number of thread:", num_thread)
                    print("\tTotally find", len(plain_out))
                    print("\tTime cost of client is", clnt_time_cost_in_srch, "us, average is",
                        clnt_time_cost_in_srch / len(plain_out))
                    print("\tTime cost of server is", srv_time_cost_in_srch, "us, average is",
                        srv_time_cost_in_srch / len(plain_out))
                    print("\tTime cost of the whole search phase is", total_time_in_srch, "us")
                    print("\tAverage time cost is", total_time_in_srch / len(plain_out), "us")
                    print("\tTotal data exchanged are", total_data_size, "bytes\n")

        return 0

    def benchmark_opt_deletions():
        rose_clnt = RoseClient()
        rose_srv = RoseServer()
        cipher_out = []
        labels = []
        plain_out = []
        portion_to_del = [0.0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2, 0.22, 0.24, 0.26, 0.28, 0.3, 0.32, 0.34, 0.36, 0.38, 0.4, 0.42, 0.44, 0.46, 0.48, 0.5]
        srch_count = [0]
        total_time_in_srch = 0
        clnt_time_cost_in_srch = 0
        srv_time_cost_in_srch = 0
        total_data_size = 0
        keyword_to_delete = "40"
        tpd_T = ""
        tpd_L = ""
        L = ""
        R = ""
        D = ""
        C = ""
        counter = 0
        indices = set()
        t = data_to_encrypt[keyword_to_delete]

        print("\n\nBegin test optimal deletions\n")

        for number_of_srch in srch_count:
            for por in portion_to_del:
                num_encrypted = 0
                num_deleted = int(por * len(t))

                rose_clnt.setup()
                rose_srv.setup()

                for ind in t:
                    rose_clnt.encrypt(L, R, D, C, op_add, keyword_to_delete, ind)
                    rose_srv.save(L, R, D, C)
                    if num_encrypted < num_deleted:
                        num_encrypted += 1
                        rose_clnt.encrypt(L, R, D, C, op_del, keyword_to_delete, ind)
                        rose_srv.save(L, R, D, C)

                fnames = data_to_encrypt[keyword_to_delete]

                cipher_out.clear()
                plain_out.clear()
                labels.clear()
                indices.clear()

                cipher_out.reserve(300000)
                plain_out.reserve(300000)
                labels.reserve(300000)
                indices.reserve(300000)

                # Search stage 1: generate trapdoor
                start = datetime.datetime.now()
                rose_clnt.trapdoor(keyword_to_delete, tpd_L, tpd_T, L, R, D, C)
                end = datetime.datetime.now()
                elapsed = (end - start).total_seconds() * 1e6
                clnt_time_cost_in_srch = elapsed
                total_data_size = 32 + 32 + 32 + 16 + 1 + 32 * 2 + 33 + CIPHER_SIZE

                # Search stage 2: find ciphertexts
                start = datetime.datetime.now()
                rose_srv.search(cipher_out, tpd_L, tpd_T, L, R, D, C)
                end = datetime.datetime.now()
                elapsed = (end - start).total_seconds() * 1e6
                srv_time_cost_in_srch = elapsed
                total_data_size += len(cipher_out) * CIPHER_SIZE

                # Search stage 3: decrypt and re-encrypt ciphertexts
                start = datetime.datetime.now()
                rose_clnt.decrypt(plain_out, keyword_to_delete, cipher_out)
                end = datetime.datetime.now()
                elapsed = (end - start).total_seconds() * 1e6
                clnt_time_cost_in_srch += elapsed
                total_data_size += len(plain_out) * sizeof(int)

                total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch

                print("Searching for keyword:", keyword_to_delete)
                print("Deletion Portion:", por, "and deleted entries is:", int(por * len(fnames)))
                print("\tTotally find", len(plain_out))
                print("\tTime cost of client is", clnt_time_cost_in_srch, "us, average is",
                    clnt_time_cost_in_srch / len(plain_out))
                print("\tTime cost of server is", srv_time_cost_in_srch, "us, average is",
                    srv_time_cost_in_srch / len(plain_out))
                print("\tTime cost of the whole search phase is", total_time_in_srch, "us")
                print("\tAverage time cost is", total_time_in_srch / len(plain_out), "us")
                print("\tTotal data exchanged are", total_data_size, "bytes\n")

        return 0

if __name__ == "__main__":
    benchmark = SSEBenchmark()
    
    benchmark.Setup("sse_data_test")
    benchmark.benchmark_search()
    benchmark.benchmark_deletions()
    benchmark.benchamark_deletion_in_parallel()
    benchmark.benchmark_opt_deletions()
