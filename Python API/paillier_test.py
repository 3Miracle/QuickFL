#-- coding:UTF-8 --
"""Paillier encryption library for partially homomorphic encryption."""

#
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import random
import ctypes
from joblib import Parallel, delayed
import numpy as np
import time
import json

import gmpy_math
from fixedpoint import FixedPointNumber
#from line_profiler import LineProfiler

libhcs = ctypes.CDLL('/user/local/libhcs.so')

array_encrypt = libhcs.array_encrypt
array_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
array_encrypt.restype = None

QAT_initial = libhcs.QAT_initial
QAT_initial.argtypes = [ctypes.c_void_p]
QAT_initial.restype = ctypes.c_void_p




class PaillierKeypair(object):
    def __init__(self):
        pass

    @staticmethod
    def generate_keypair(n_length=2048):
        """return a new :class:`PaillierPublicKey` and :class:`PaillierPrivateKey`.
        """
        p = q = n = None
        numinst = ctypes.c_ushort()
        numinst_ptr = ctypes.pointer(numinst)
        pCyinstance_handle = QAT_initial(numinst_ptr)

        n = 16816259347332836780309998028941743358287925349776132230998924187274567002860099726783036051260978615040660168188619972048220255673894369165009375950290161445364693744524524595813588881664455061518925798080955464089405217902287714874999997894272106693650420295330078476644819736648414526778495271598885617421362729762471287693104006777439869245603097058286163471624127436138066734083616192720741224484628070490326736134753665182568384497511347086550442746091217100346836157773463518086256506985855670513165603236333657078659165126055966947319019605543178643978357878730917836516224238002801692773899313032973784090983
        p = 116530600315925021126798876254649991373496956879720715476969119549772948522084577749173987587094582751002614383640759004688604982515139878996508300763421653020931915966555539374024330868202139200541647050717688638591848462807507388125404076614047639362787049147168643187018402497141330597149394179514452502879
        q = 144307669416809261009944376622120270474374705965180900371207199090066682928615570523048779850213106187581154553413481708442433931837990076878961583620814929817138948252794425435684062636288917417732352375606905558616322632797468042422809760405289747898728539536734397479497916538484650089260125805448325526777

        public_key = PaillierPublicKey(n,pCyinstance_handle)
        private_key = PaillierPrivateKey(public_key, p, q)

        return public_key, private_key


class PaillierPublicKey(object):
    """Contains a public key and associated encryption methods.
    """

    
    def __init__(self, n,pCyinstance_handle):
        self.g = n + 1
        self.n = n
        self.nsquare = n * n
        self.max_int = n // 3 - 1
        self.pCyinstance_handle = pCyinstance_handle

    def __repr__(self):
        hashcode = hex(hash(self))[2:]
        return "<PaillierPublicKey {}>".format(hashcode[:10])

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def apply_obfuscator(self, ciphertext, random_value=None):
        """
        """
        r = random_value or random.SystemRandom().randrange(1, self.n)
        obfuscator = gmpy_math.powmod(r, self.n, self.nsquare)

        return (ciphertext * obfuscator) % self.nsquare

    def raw_encrypt(self, plaintext, random_value=None):
        """
        """
        if not isinstance(plaintext, int):
            raise TypeError("plaintext should be int, but got: %s" %
                            type(plaintext))

        if plaintext >= (self.n - self.max_int) and plaintext < self.n:
            # Very large plaintext, take a sneaky shortcut using inverses
            neg_plaintext = self.n - plaintext  # = abs(plaintext - nsquare)
            neg_ciphertext = (self.n * neg_plaintext + 1) % self.nsquare
            ciphertext = gmpy_math.invert(neg_ciphertext, self.nsquare)
        else:
            ciphertext = (self.n * plaintext + 1) % self.nsquare

        ciphertext = self.apply_obfuscator(ciphertext, random_value)

        return ciphertext

    def encrypt(self, value, precision=None, random_value=None):
        """Encode and Paillier encrypt a real number value.
        """
        if isinstance(value, FixedPointNumber):
            value = value.decode()
        encoding = FixedPointNumber.encode(value, self.n, self.max_int, precision)
        obfuscator = random_value or 1
        ciphertext = self.raw_encrypt(encoding.encoding, random_value=obfuscator)
        encryptednumber = PaillierEncryptedNumber(self, ciphertext, encoding.exponent)
        if random_value is None:
            encryptednumber.apply_obfuscator()

        return encryptednumber
    def matrix_encrypt(self, A, precision=None):
        """Encode and Paillier encrypt a matrix real number value,coroutines encrypt
        """
        og_shape = A.shape
        if len(A.shape) == 1:
            A = np.expand_dims(A, axis=0)
        A = np.reshape(A, (1, -1))
        A = np.squeeze(A)

        # Encode all the element of matrix
        encoding = Parallel(n_jobs=80)(delayed(FixedPointNumber.encode)(num, self.n, self.max_int, precision) for num in A)

        length = len(encoding)
        # Serialize and Convert to Ctypes c_char_p, so that Python can handle it
        encoding_list = []
        for i in range(length):
            encoding_list.append(ctypes.c_char_p(str(encoding[i].encoding).encode('utf-8')))
        encoding_array = (ctypes.c_char_p * length)(*encoding_list)

        # Encrypt all the element of encoding_list
        length1 = ctypes.c_int(length)
        c_charp_array = ctypes.c_char_p * length
        c_char_array = c_charp_array()
        time_start = time.perf_counter()
        # "array_encrypt" is the top-level interface of the QAT paillier acceleration software stack
        array_encrypt(ctypes.byref(c_char_array),encoding_array,length1,self.pCyinstance_handle)
        # Receive encrypted data from the QAT software stack via Ctypes
        encrypted_list = []
        for i in range(length):
            encrypted_list.append(int(c_char_array[i]))

        encryptednumber_list = []
        for i in range(length):
            encryptednumber_list.append(PaillierEncryptedNumber(self, encrypted_list[i], encoding[i].exponent))

        return encryptednumber_list


class PaillierPrivateKey(object):
    """Contains a private key and associated decryption method.
    """

    def __init__(self, public_key, p, q):
        if not p * q == public_key.n:
            raise ValueError("given public key does not match the given p and q")
        if p == q:
            raise ValueError("p and q have to be different")
        self.public_key = public_key
        if q < p:
            self.p = q
            self.q = p
        else:
            self.p = p
            self.q = q
        self.psquare = 13579380809989864633645717232528548872628203730821696929229557137666713718509806652959888286557445304096534961956646747786589702521081054101154594878798596896645309313920782075618746189156185595775589890335705085484168191333925176619303440917723744512353995523583915451788878006653609594701786185557938694099224866144906820574642614957245954834491039430946481122298096611217841416790411997730577446403084019508075030942259474526585612682584895935562904251316108753448916646601824900935167056790505333941788000420307469868315607747641466651798053173100957459427072961288551164208270683318863037394868060400467503288641
        self.qsquare = 20824703452511106921645277683648477681655219106282355213330368680611428897311260121393547262535264361405003110769273279153737321571705856394546926897027213180132278244589271408729054059174496222935044725305720553777025274464087627709884711160176948740010327349804054822027879537281592963740265146266753621217062991771560365205984573208618346084154625826324440406389381287828867991957357861416755741184409922219315635969891537028776939691206966163510580318225179200437466476794998898005410159488774698979757547774648561272999755057452667073528831433378714398896803128223183069336781013619029968616828138929874544007729
        self.q_inverse = gmpy_math.invert(self.q, self.p)
        self.hp = 63407375798360197325676531266048474559000585639101724905991745165176500784570958838842824629912967677161861657954517627939443938004173651385572003377316958012770700893167311291064965819476181678386874805768052996541679828413567903599507562176631619999976706909802942558120195443114812524050464704157030843364
        self.hq = 65786057063571454751881737353709004581590464357001823730075825881494010258146472450705687360856181056898015260734969300241493580344465099646155158649067135782152995987950071603676690100529352136370037755628075047842408784577172663756358533218340755425488281946490726535811375778117963300357939546201332717726

    def __eq__(self, other):
        return self.p == other.p and self.q == other.q

    def __hash__(self):
        return hash((self.p, self.q))

    def __repr__(self):
        hashcode = hex(hash(self))[2:]

        return "<PaillierPrivateKey {}>".format(hashcode[:10])

    def h_func(self, x, xsquare):
        """Computes the h-function as defined in Paillier's paper page.
        """
        return gmpy_math.invert(self.l_func(gmpy_math.powmod(self.public_key.g,
                                                             x - 1, xsquare), x), x)

    def l_func(self, x, p):
        """computes the L function as defined in Paillier's paper.
        """

        return (x - 1) // p

    def crt(self, mp, mq):
        """the Chinese Remainder Theorem as needed for decryption.
           return the solution modulo n=pq.
       """
        u = (mp - mq) * self.q_inverse % self.p
        x = (mq + (u * self.q)) % self.public_key.n

        return x

    def raw_decrypt(self, ciphertext):
        """return raw plaintext.
        """
        if not isinstance(ciphertext, int):
            raise TypeError("ciphertext should be an int, not: %s" %
                            type(ciphertext))

        mp = self.l_func(gmpy_math.powmod(ciphertext,
                                          self.p - 1, self.psquare),
                         self.p) * self.hp % self.p

        mq = self.l_func(gmpy_math.powmod(ciphertext,
                                          self.q - 1, self.qsquare),
                         self.q) * self.hq % self.q

        return self.crt(mp, mq)

    def decrypt(self, encrypted_number):
        """return the decrypted & decoded plaintext of encrypted_number.
        """
        if not isinstance(encrypted_number, PaillierEncryptedNumber):
            raise TypeError("encrypted_number should be an PaillierEncryptedNumber, \
                             not: %s" % type(encrypted_number))

        if self.public_key != encrypted_number.public_key:
            raise ValueError("encrypted_number was encrypted against a different key!")

        encoded = self.raw_decrypt(encrypted_number.ciphertext(be_secure=False))
        encoded = FixedPointNumber(encoded,
                                   encrypted_number.exponent,
                                   self.public_key.n,
                                   self.public_key.max_int)
        decrypt_value = encoded.dedeco()

        return decrypt_value


class PaillierEncryptedNumber(object):
    """Represents the Paillier encryption of a float or int.
    """

    def __init__(self, public_key, ciphertext, exponent=0):
        self.public_key = public_key
        self.__ciphertext = ciphertext
        self.exponent = exponent
        self.__is_obfuscator = False

        if not isinstance(self.__ciphertext, int):
            raise TypeError("ciphertext should be an int, not: %s" % type(self.__ciphertext))

        if not isinstance(self.public_key, PaillierPublicKey):
            raise TypeError("public_key should be a PaillierPublicKey, not: %s" % type(self.public_key))

    def ciphertext(self, be_secure=True):
        """return the ciphertext of the PaillierEncryptedNumber.
        """
        if be_secure and not self.__is_obfuscator:
            self.apply_obfuscator()

        return self.__ciphertext

    def apply_obfuscator(self):
        """ciphertext by multiplying by r ** n with random r
        """
        self.__ciphertext = self.public_key.apply_obfuscator(self.__ciphertext)
        self.__is_obfuscator = True

    def __add__(self, other):
        if isinstance(other, PaillierEncryptedNumber):
            return self.__add_encryptednumber(other)
        else:
            return self.__add_scalar(other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        return self + (other * -1)

    def __rsub__(self, other):
        return other + (self * -1)

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __truediv__(self, scalar):
        return self.__mul__(1 / scalar)

    def __mul__(self, scalar):
        """return Multiply by an scalar(such as int, float)
        """
        if isinstance(scalar, FixedPointNumber):
            scalar = scalar.decode()
        encode = FixedPointNumber.encode(scalar, self.public_key.n, self.public_key.max_int)
        plaintext = encode.encoding

        if plaintext < 0 or plaintext >= self.public_key.n:
            raise ValueError("Scalar out of bounds: %i" % plaintext)

        if plaintext >= self.public_key.n - self.public_key.max_int:
            # Very large plaintext, play a sneaky trick using inverses
            neg_c = gmpy_math.invert(self.ciphertext(False), self.public_key.nsquare)
            neg_scalar = self.public_key.n - plaintext
            ciphertext = gmpy_math.powmod(neg_c, neg_scalar, self.public_key.nsquare)
        else:
            ciphertext = gmpy_math.powmod(self.ciphertext(False), plaintext, self.public_key.nsquare)

        exponent = self.exponent + encode.exponent

        return PaillierEncryptedNumber(self.public_key, ciphertext, exponent)

    def increase_exponent_to(self, new_exponent):
        """return PaillierEncryptedNumber:
           new PaillierEncryptedNumber with same value but having great exponent.
        """
        if new_exponent < self.exponent:
            raise ValueError("New exponent %i should be great than old exponent %i" % (new_exponent, self.exponent))

        factor = pow(FixedPointNumber.BASE, new_exponent - self.exponent)
        new_encryptednumber = self.__mul__(factor)
        new_encryptednumber.exponent = new_exponent

        return new_encryptednumber

    def __align_exponent(self, x, y):
        """return x,y with same exponet
        """
        if x.exponent < y.exponent:
            x = x.increase_exponent_to(y.exponent)
        elif x.exponent > y.exponent:
            y = y.increase_exponent_to(x.exponent)

        return x, y

    def __add_scalar(self, scalar):
        """return PaillierEncryptedNumber: z = E(x) + y
        """
        if isinstance(scalar, FixedPointNumber):
            scalar = scalar.decode()
        encoded = FixedPointNumber.encode(scalar,
                                          self.public_key.n,
                                          self.public_key.max_int,
                                          max_exponent=self.exponent)
        return self.__add_fixpointnumber(encoded)

    def __add_fixpointnumber(self, encoded):
        """return PaillierEncryptedNumber: z = E(x) + FixedPointNumber(y)
        """
        if self.public_key.n != encoded.n:
            raise ValueError("Attempted to add numbers encoded against different public keys!")

        # their exponents must match, and align.
        x, y = self.__align_exponent(self, encoded)

        encrypted_scalar = x.public_key.raw_encrypt(y.encoding, 1)
        encryptednumber = self.__raw_add(x.ciphertext(False), encrypted_scalar, x.exponent)

        return encryptednumber

    def __add_encryptednumber(self, other):
        """return PaillierEncryptedNumber: z = E(x) + E(y)
        """
        if self.public_key != other.public_key:
            raise ValueError("add two numbers have different public key!")

        # their exponents must match, and align.
        x, y = self.__align_exponent(self, other)

        encryptednumber = self.__raw_add(x.ciphertext(False), y.ciphertext(False), x.exponent)

        return encryptednumber

    def __raw_add(self, e_x, e_y, exponent):
        """return the integer E(x + y) given ints E(x) and E(y).
        """
        ciphertext = gmpy_math.mpz(e_x) * gmpy_math.mpz(e_y) % self.public_key.nsquare

        return PaillierEncryptedNumber(self.public_key, int(ciphertext), exponent)

if __name__ == '__main__': 
    public_key, private_key = PaillierKeypair.generate_keypair()
    a = np.random.randint(-100,100,(100,1000))
    _ = public_key.matrix_encrypt(a)
