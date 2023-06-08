from utils import OP, KUPRF

P = KUPRF()
key1 = P.gen_key()
# print(int.from_bytes(key1, byteorder='big'))

a = P.compute(key1, "", "", OP.OP_ADD)
# print(int.from_bytes(a, byteorder='big'))
print(a)

key2 = P.gen_key()
# print(int.from_bytes(key2, byteorder='big'))

token = P.get_update_token(key2, key1)
# print(int.from_bytes(token, byteorder='big'))

b = P.compute(key2, "", "", OP.OP_ADD)
# print(int.from_bytes(b, byteorder='big'))
print(b)

c = P.update_result(b, token)
# print(int.from_bytes(c, byteorder='big'))
print(c)
