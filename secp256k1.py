# downloaded from https://github.com/user8547/fast-ecc-python

# curve implementation in python
class Curve:

    def __init__(self):
        # curve parameters for secp256k1
        # http://perso.univ-rennes1.fr/sylvain.duquesne/master/standards/sec2_final.pdf
        self.a = 0
        self.b = 7
        self.p = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
        gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
        gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
        self.g = [gx,gy]
        self.n = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141

    def valid(self, point):
        xP = point[0]

        if xP==None:
            return False

        yP = point[1]
        return yP**2 % self.p == (pow(xP, 3, self.p) + self.a*xP + self.b) % self.p

    def decompress(self, compressed):
        byte = compressed[0]

        # point at infinity
        if byte == b"\x00":
            return [None,None]

        xP = int.from_bytes(compressed[1:], byteorder = 'big')
        ysqr = (pow(xP, 3, self.p) + self.a*xP + self.b) % self.p
        assert self.p % 4 == 3
        yP = pow(ysqr, (self.p + 1)//4, self.p)
        assert pow(yP, 2, self.p)==ysqr
        if yP % 2:
            if byte == b"\x03":
                return [xP,yP]
            return [xP, -yP % self.p]
        if byte == b"\x02":
            return [xP,yP]
        return [xP, -yP % self.p]

    def compress(self, P):

        if P[0] == None:
            return b"\x00" + b"\x00"*32

        byte = b"\x02"
        if P[1] % 2:
            byte = b"\x03"
        return byte + P[0].to_bytes(32, byteorder = 'big')

    def inv(self, point):
        xP = point[0]

        if xP==None:
            return [None,None]

        yP = point[1]
        R = [xP,-yP % self.p]
        return R

    def add(self, P, Q):

        # P+P=2P
        if P==Q:
            return self.dbl(P)

        # P+0=P
        if P[0]==None:
            return Q
        if Q[0]==None:
            return P

        # P+-P=0
        if Q==self.inv(P):
            return [None,None]

        xP = P[0]
        yP = P[1]
        xQ = Q[0]
        yQ = Q[1]
        s = (yP - yQ) * pow(xP - xQ, -1, self.p) % self.p
        xR = (pow(s,2,self.p) - xP -xQ) % self.p
        yR = (-yP + s*(xP-xR)) % self.p
        R = [xR,yR]
        return R

    def dbl(self, P):
        # 2*0=0
        if P[0]==None:
            return P

        # yP==0
        if P[1]==0:
            return [None,None]

        xP = P[0]
        yP = P[1]
        s = (3*pow(xP,2,self.p)+self.a) * pow(2*yP, -1, self.p) % self.p
        xR = (pow(s,2,self.p) - 2*xP) % self.p
        yR = (-yP + s*(xP-xR)) % self.p
        R = [xR,yR]
        return R

    def mul(self, P, k):
        # x0=0
        if P[0]==None:
            return P

        N = P
        R = [None,None]

        while k:
            bit = k % 2
            k >>= 1
            if bit:
                R = self.add(R,N)
            N = self.dbl(N)

        return R
