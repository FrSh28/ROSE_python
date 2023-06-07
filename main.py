from rose_client import RoseClient
from rose_server import RoseServer
from sse_benchmark import SSEBenchmark

def test_sse():
    rose_client = RoseClient()
    rose_server = RoseServer(True)
    result_plain = []
    result_cip = []
    L, R, D, C, tpd_L, tpd_T = "", "", "", "", "", ""

    rose_client.setup()
    rose_server.setup()

    for i in range(200):
        rose_client.encrypt(L, R, D, C, "op_add", "abc", i)
        rose_server.save(L, R, D, C)

    for i in range(20, 300):
        rose_client.encrypt(L, R, D, C, "op_add", "abc", i)
        rose_server.save(L, R, D, C)

    for i in range(30, 400):
        rose_client.encrypt(L, R, D, C, "op_add", "abc", i)
        rose_server.save(L, R, D, C)

    for i in range(40, 500):
        rose_client.encrypt(L, R, D, C, "op_add", "abc", i)
        rose_server.save(L, R, D, C)

    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C)
    rose_server.save(L, R, D, C)
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C)
    rose_server.save(L, R, D, C)
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C)
    rose_server.save(L, R, D, C)
    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C)
    rose_server.save(L, R, D, C)

    for i in range(400):
        rose_client.encrypt(L, R, D, C, "op_del", "abc", i)
        rose_server.save(L, R, D, C)

    rose_client.save_data()
    rose_client.load_data()
    rose_server.save_data()
    rose_server.load_data()

    rose_client.trapdoor("abc", tpd_L, tpd_T, L, R, D, C)
    result_cip.clear()
    result_plain.clear()
    # rose_server.search(result_cip, tpd_L, tpd_T, L, R, D, C)
    rose_server.search_with_parallel_del(result_cip, tpd_L, tpd_T, L, R, D, C, 6)
    rose_client.decrypt(result_plain, "abc", result_cip)

    for itr in result_plain:
        print(itr)

    print("----------------------------------------")
    print("Totally found", len(result_plain), "records")

    return 0

def benchmark():
    benchmark = SSEBenchmark()
    
    benchmark.Setup("sse_data_test")
    # benchmark.benchmark_gen_add_cipher()
    # benchmark.benchmark_gen_del_cipher()
    benchmark.benchmark_search()
    benchmark.benchmark_deletions()
    benchmark.benchamark_deletion_in_parallel()
    benchmark.benchmark_opt_deletions()

if __name__ == "__main__":
    KUPRF.init()

    benchmark()
    # test_sse()

    KUPRF.clean()
