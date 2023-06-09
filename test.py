from utils import OP, KUPRF

P = KUPRF()
key1 = P.gen_key()
# key1 = (P.curve.n-234235221).to_bytes(32, byteorder='big')
# print(int.from_bytes(key1, byteorder='big'))

a = P.compute(key1, "", "", OP.OP_ADD)
# print(int.from_bytes(a, byteorder='big'))
print(a)

key2 = P.gen_key()
# key2 = (P.curve.n-2).to_bytes(32, byteorder='big')
# print(int.from_bytes(key2, byteorder='big'))

token = P.get_update_token(key2, key1)
# print(int.from_bytes(token, byteorder='big'))
print(token)

b = P.compute(key2, "", "", OP.OP_ADD)
# print(int.from_bytes(b, byteorder='big'))
print(b)

c = P.update_result(b, token)
# print(int.from_bytes(c, byteorder='big'))
print(c)

key3 = P.merge_update_token(key2, token)
print(key3 == key1)
# d = P.compute(key3, "", "", OP.OP_ADD)
# print(d)
