# Basics of Elliptic Curve Cryptography implementation on Python
from builtins import str
import hashlib
import hmac
import random
import timeit
import time

from Components import Complex
from Components import EC, HalfComplex
from Components import Math
from Components.BonehFranklin import BonehFranklin
from Components.ECPoint import ECPoint
from Components.Fp2Point import Fp2Point
from Components.Fp2Element import Fp2Element
from Components.TatePairing import TatePairing
from Components.HalfComplex import HalfComplex
from Crypto.Cipher import AES

from ecdsa import SigningKey, VerifyingKey, NIST384p

"""Globális paraméterek"""
# Master Secret Key
gamma = None
# Global parameters
P = None
gammaP = None
ec = None
# OBU
Qv = None
gammaQv = None
ownToken = None
RSUToken = None
t = 0
# RSU
Qr = None
gammaQr = None
xi = None
xiQr = None
# Local user list and global blacklist
users = []
blacklist = []


def main():
    """ Főmenü szerkezete """
    print()
    print("################################# MAIN MENU #################################")
    print("1. Regenerate parameters")
    print("2. Show parameters")
    print("3. Setup")
    print("4. Incident message send/recieve")
    print("5. Exposure message send/recieve")
    print("6. Pairing tests")
    print("7. Performance tests")
    print("8. Exit")

    print("Please, choose an options, and type the number of it!")
    run = int(input())

    if run == 1:
        reGenParams()
    if run == 2:
        showParams()
    if run == 3:
        setup()
    if run == 4:
        incident()
    if run == 5:
        exposure()
    if run == 6:
        pairing()
    if run == 7:
        performanceTest()
    if run == 8:
        pass


################################# INITIALIZATION #################################
def init():
    """
        A rendszer inicializálása:
            - Elliptikus görbe osztályának példányosítása
            - Alapparaméterek beolvasása fájlból
    """
    global ec
    ec = EC.EC()
    ec.basepoint = ec.at(None)
    # reGenParams()
    parameters()


def parameters():
    """Alapparamétererk beolvasása fájlból a globális változókba"""
    global ec
    # Master Secret Key
    global gamma
    # Global parameters
    global P
    global gammaP
    # OBU
    global Qv
    global gammaQv
    global ownToken
    global RSUToken
    # RSU
    global Qr
    global gammaQr
    global xi
    global xiQr
    # Local user list and global blacklist
    global users
    global blacklist

    ################################# gamma #################################
    with open('params/gamma', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        gamma = int(content[0])
    ################################# P #################################
    with open('params/P', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        P = ECPoint(ec, coord[0], coord[1])
    ################################# gammaP #################################
    with open('params/gammaP', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        gammaP = ECPoint(ec, coord[0], coord[1])
    ################################# Qv #################################
    with open('params/Qv', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        Qv = ECPoint(ec, coord[0], coord[1])
    ################################# gammaQv #################################
    with open('params/gammaQv', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        gammaQv = ECPoint(ec, coord[0], coord[1])
    ################################# ownToken #################################
    with open('params/ownToken', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        ownToken = ECPoint(ec, coord[0], coord[1])
    ################################# RSUToken #################################
    with open('params/RSUToken', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        RSUToken = ECPoint(ec, coord[0], coord[1])
    ################################# Qr #################################
    with open('params/Qr', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        Qr = ECPoint(ec, coord[0], coord[1])
    ################################# gammaQr #################################
    with open('params/gammaQr', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        coord = []
        for line in content:
            coord.append(int(line))
        gammaQr = ECPoint(ec, coord[0], coord[1])
    ################################# xi #################################
    with open('params/xi', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        xi = int(content[0])
    ################################# xiQr #################################
    xiQr = ec.mulJ(Qr, xi)
    ################################# users #################################
    with open('params/users', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        for user in content:
            users.append(HalfComplex(ec.q, int(user)))
    ################################# blacklist #################################
    with open('params/blacklist', 'r') as filehandle:
        content = [current_place.rstrip() for current_place in filehandle.readlines()]
    if content:
        for user in content:
            coord = user.split(" ")
            blacklist.append(Fp2Point(int(coord[0]), int(coord[1])))


def reGenParams():
    """Alapparaméterek újragenerálása"""
    # Master Secret Key
    global gamma
    # Global parameters
    global P
    global gammaP
    # OBU
    global Qv
    global gammaQv
    global ownToken
    global RSUToken
    # RSU
    global Qr
    global gammaQr
    global xi
    # Local user list and global blacklist
    global users
    global blacklist

    ################################# gamma #################################
    gamma = random.getrandbits(256)
    while ec.q < gamma:
        gamma = random.getrandbits(256)
    saveConstant('params/gamma', gamma)
    ################################# P #################################
    P = ec.at_gen(None)
    savePoint('params/P', P)
    ################################# gammaP #################################
    gammaP = ec.mulJ(P, gamma)
    savePoint('params/gammaP', gammaP)
    ################################# Qr #################################
    RSU_RID = 'RSU001'
    Qr = ec.at(RSU_RID)
    savePoint('params/Qr', Qr)
    ################################# gammaQr #################################
    gammaQr = ec.mulJ(Qr, gamma)
    savePoint('params/gammaQr', gammaQr)
    ################################# xi #################################
    xi = random.getrandbits(128)
    while ec.q < xi:
        xi = random.getrandbits(128)
    saveConstant('params/xi', xi)
    ################################# Qv #################################
    OBU_RID = 'BH41ASZ'
    Qv = ec.at_gen(OBU_RID)
    savePoint('params/Qv', Qv)
    ################################# gammaQv #################################
    gammaQv = ec.mulJ(Qv, gamma)
    savePoint('params/gammaQv', gammaQv)
    ################################# ownToken #################################
    ownToken = ec.mulJ(Qv, xi)
    savePoint('params/ownToken', ownToken)
    ################################# RSUToken #################################
    RSUToken = ec.mulJ(Qr, xi)
    savePoint('params/RSUToken', RSUToken)
    ################################# users #################################
    genUsers()
    ################################# blacklist #################################
    genBlacklist()

    main()


def showParams():
    """Alapparaméterek kiíratása a képernyőre"""
    print("################################# PARAMETERS #################################")
    print('Gamma             :', gamma)
    print('P                 :', P.toString())
    print('gammaP            :', gammaP.toString())
    OBU_RID = 'BH41ASZ'
    print("OBU_RID           : " + OBU_RID)
    print("Qv                : " + Qv.toString())
    print("gammaQv           : " + gammaQv.toString())
    print("ownToken          : " + ownToken.toString())
    print("RSUToken          : " + RSUToken.toString())
    RSU_RID = 'RSU001'
    print("RSU_RID           : " + RSU_RID)
    print("Qr                : " + Qr.toString())
    print("gammaQr           : " + gammaQr.toString())
    print('Local secret xi   :', xi)

    main()


################################# SETUP #################################
def setup():
    """Kommunikáció felállítása [TDK - 5.5.2]"""
    global ec
    global users
    global blacklist
    global ownToken
    global RSUToken
    global t
    print("################################# SETUP #################################")
    print()
    print("################################# OBU #################################")
    t = random.getrandbits(128)
    s = random.getrandbits(128)
    start = timeit.default_timer()
    print("Generating parameters for request message")
    print('t                                     =', t)
    A1 = TatePairing.computeF(TatePairing, gammaQv, Qr, ec).toString()
    print('A1 = e(gammaQv, Qr)                   =', A1)
    sgammaQv = ec.mulJ(gammaQv, s)
    msg = Qv.toString() + ";" + A1 + ";" + str(t) + ";" + sgammaQv.toString()
    #   n is the length of the message
    u, v = BonehFranklin.encryp(BonehFranklin, msg, Qr, gammaP, P, ec)
    print("Send the request message to RSU ------> (c = M1 = (u, v) = Enc(Qv, A1, t)")
    stop = timeit.default_timer()
    print('Time of SETUP PHASE 1 (1 x TatePairing, 1 x BonehFranklinEnc:', stop - start)

    print("################################# RSU #################################")
    start = timeit.default_timer()
    print("Decrypt the recieved request message (M1)")
    decM1 = BonehFranklin.decrypt(BonehFranklin, u, v, gammaQr, ec)
    print('Decrypted message                     =', decM1)
    senderID, recieved_A1, recieved_t, recieved_sgQv = decM1.split(";")
    senderID = senderID.split(" ")
    senderID = Fp2Point(int(senderID[0]), int(senderID[1]))
    recieved_t = int(recieved_t)
    recieved_sgQv = recieved_sgQv.split(" ")
    recieved_sgQv = Fp2Point(int(recieved_sgQv[0]), int(recieved_sgQv[1]))
    print('Sender ID                             =', senderID.toString())
    print('Recieved A1                           =', recieved_A1)
    print('Recieved t                            =', recieved_t)
    print('#################################')
    print('Check Revocation List/Blacklist')
    noRL = False
    try:
        blacklist.index(senderID.toString())
    except ValueError:
        noRL = True
    print('Valid ID                              =', noRL)
    print('#################################')
    print('Check validity of the car')
    A1CheckSum = TatePairing.computeF(TatePairing, senderID, gammaQr, ec).toString()
    hasMSkey = recieved_A1 == A1CheckSum
    print('#################################')
    print('A1 ?= e(Qv, gammaQr)                  =', hasMSkey)
    ################################ VALID CAR? #################################
    if hasMSkey and noRL:
        #         Create token for the new user
        token = ec.mulJ(Qv, xi)
        tokenT = ec.mulJ(token, recieved_t)  # txiQv
        xisgQv = ec.mulJ(recieved_sgQv, xi)
        #         Add new user to the users list --> Anonymized User List e(xiQv, Qv)^gamma
        anonymizedUser = HalfComplex.HCpow(HalfComplex, TatePairing.computeF(TatePairing, token, Qv, ec), gamma, ec.q)
        users.append(anonymizedUser)
        #         Message for the new user: (tsxiQv, tsxiQr, tsQr)
        msg = tokenT.toString() + ";" + xisgQv.toString()
        print("Send for the new user: (tokenT, xisgQv)")
    stop = timeit.default_timer()
    print('Time of SETUP (2 x TatePairing, 1 x BonehFranklinDec, 8 x multiplication with scalar):', stop - start)

    print("################################# OBU #################################")
    Qv_xiQr = TatePairing.computeF(TatePairing, Qv, xiQr, ec)
    gammaQv_xiQr = TatePairing.computeF(TatePairing, gammaQv, xiQr, ec)
    t_inv = Math.modular_inverse(t, ec.r)
    s_inv = Math.modular_inverse(s, ec.r)
    start = timeit.default_timer()
    #     Calculating the ownToken and RSU checksum
    ownToken = ec.mulJ(tokenT, t_inv)
    RSUcheck = ec.mulJ(xisgQv, s_inv)
    print("Check the TOKEN validity ------> e(xiQv, Qr) =? e(Qv, xiQr)")
    xiQv_Qr = TatePairing.computeF(TatePairing, ownToken, Qr, ec)
    print("Check the RSU validity ------> e(xigammaQv, Qr) =? e(gammaQv, xiQr)")
    xigammaQv_Qr = TatePairing.computeF(TatePairing, RSUcheck, Qr, ec)
    checkToken = Qv_xiQr.real == xiQv_Qr.real and gammaQv_xiQr.real == xigammaQv_Qr.real
    print("Multiply the recieved TOKEN with the inverse of t and with the inverse of s to get the real TOKEN")
    print('The RSU and the got TOKEN valid       =', checkToken)
    print('OBUs own TOKEN                        =', ownToken.toString())
    stop = timeit.default_timer()
    print('Time of SETUP PHASE 2 (2 x TatePairing, 2 x ModInverse, 3 x multiplication with scalar):', stop - start)
    print()


#     main()


################################# INCIDENT #################################
def incident():
    """Incidens (baleset, dugó, stb.) bejelentése, üzenetszórás [TDK - 5.5.3]"""
    print("################################# INCIDENT #################################")
    print()
    print("################################# OBU #################################")
    M = "ALERT 2"
    print("Generating a random 'a', then create AID = a * Qv")
    a = random.getrandbits(128)
    b = random.getrandbits(128)
    print('a                                     =', a)
    print('b                                     =', b)
    AID = ec.mulJ(Qv, a)
    print('AID = a * Qv                          =', AID.toString())
    print("Generate the point of the message and the timestamp")
    t = time.time()
    msg_point = ec.at(M + str(t))
    print('H(M||T)                               =', msg_point.toString())
    print("Create A1 for sendig incident")
    A1 = ec.mulJ(ownToken, a)
    print('A1 = a * xi * Qv                      =', A1.toString())
    print("Create A3 for sendig incident")
    a_inv = Math.modular_inverse(a, ec.r)
    xigammaQv = ec.mulJ(gammaQv, xi)
    A3 = ec.mulJ(xigammaQv, a_inv)
    print('A3 = a^-1xigammaQv                    =', A3.toString())
    start = timeit.default_timer()
    print("Create A2 for sendig incident")
    bMsg_hash = ec.mulJ(msg_point, b)
    agammaQv = ec.mulJ(gammaQv, a)
    A2 = ec.add2(bMsg_hash, agammaQv)
    print('A2 = bH(M||T) + agammaQv              =', A2.toString())
    bP = ec.mulJ(P, b)
    print("Broadcast message (AID, A1, A2, A3, bP, M, T)")
    stop = timeit.default_timer()
    print('Time of INCIDENT PHASE 1 (6 x multiplication with scalar, 2 x hash, 1 x modInverse):', stop - start)

    print("################################# OBU #2 / RSU #################################")
    start = timeit.default_timer()
    print("Check the time stamp")
    validSender = TatePairing.computeF(TatePairing, AID, xiQr, ec).real == TatePairing.computeF(TatePairing, A1, Qr, ec).real
    print('Valid sender/car          =', validSender)
    A2_P = TatePairing.computeF(TatePairing, A2, P, ec)
    AID_gammaP = TatePairing.computeF(TatePairing, AID, gammaP, ec)
    msg_point_bP = TatePairing.computeF(TatePairing, msg_point, bP, ec)
    validMsg = A2_P.real == AID_gammaP.real * msg_point_bP.real
    print('Valid message             =', validMsg)
    stop = timeit.default_timer()
    print('Time of INCIDENT PHASE 2 (4 x TatePairing):', stop - start)
    print()


#     main()


################################# EXPOSURE #################################
def exposure():
    """Leleplező üzenet küldése, rosszindulatú felhasználó bejelentése [TDK - 5.5.4]"""
    print("################################# EXPOSURE #################################")
    print()
    print("################################# OBU #1 #################################")
    M = "ALERT 2"
    print("Generating a random 'a', then create AID = a * Qv")
    a = random.getrandbits(128)
    b = random.getrandbits(128)
    print('a                                     =', a)
    print('b                                     =', b)
    AID = ec.mulJ(Qv, a)
    print('AID = a * Qv                          =', AID.toString())
    print("Generate the point of the message and the timestamp")
    t = time.time()
    msg_point = ec.at(M + str(t))
    print('H(M||T)                               =', msg_point.toString())
    print("Create A1 for sendig incident")
    A1 = ec.mulJ(ownToken, a)
    print('A1 = a * xi * Qv                      =', A1.toString())
    print("Create A3 for sendig incident")
    a_inv = Math.modular_inverse(a, ec.r)
    xigammaQv = ec.mulJ(gammaQv, xi)
    A3 = ec.mulJ(xigammaQv, a_inv)
    print('A3 = a^-1xigammaQv                    =', A3.toString())
    start = timeit.default_timer()
    print("Create A2 for sendig incident")
    bMsg_hash = ec.mulJ(msg_point, b)
    agammaQv = ec.mulJ(gammaQv, a)
    A2 = ec.add2(bMsg_hash, agammaQv)
    print('A2 = bH(M||T) + agammaQv              =', A2.toString())
    bP = ec.mulJ(P, b)
    print("Broadcast message (AID, A1, A2, A3, bP, M, T)")
    stop = timeit.default_timer()
    print('Time of EXPOSURE PHASE 1 (6 x multiplication with scalar, 2 x hash, 1 x modInverse):', stop - start)

    print("################################# RSU #################################")
    start = timeit.default_timer()
    ################################# Split the recieved message #################################
    # recM = M.split(";")
    # #     AID of the sender sAID
    # sAIDcoords = recM[0].split(" ")
    # sAID = Fp2Point(int(sAIDcoords[0]), int(sAIDcoords[1]))
    # #     A01 of the sender sA01
    # sA01coords = recM[1].split(" ")
    # sA01 = Fp2Point(int(sA01coords[0]), int(sA01coords[1]))
    # #     A02 of the sender sA02
    # sA02coords = recM[2].split(" ")
    # sA02 = Fp2Point(int(sA02coords[0]), int(sA02coords[1]))
    # #     w of the sender sW
    # sWcoords = recM[3].split(" ")
    # sW = Fp2Point(int(sWcoords[0]), int(sWcoords[1]))
    # #     A2 of the sender sA2
    # sA2coords = recM[4].split(" ")
    # sA2 = Fp2Point(int(sA2coords[0]), int(sA2coords[1]))
    # #     Recieved message
    # sMfull = recM[5]
    # sM = recM[5].split(",")
    # #     Exposed vehicle data
    # expA01coords = sM[0].split(" ")
    # expA01 = Fp2Point(int(expA01coords[0]), int(expA01coords[1]))
    # expA02coords = sM[1].split(" ")
    # expA02 = Fp2Point(int(expA02coords[0]), int(expA02coords[1]))
    # #     Recieved timestamp
    # sT = recM[6]
    ################################# Check the message and the sender validity #################################
    xi_inv = Math.modular_inverse(xi, ec.r)
    gamma_inv = Math.modular_inverse(gamma, ec.r)
    start = timeit.default_timer()
    print("Check the time stamp")
    validSender = TatePairing.computeF(TatePairing, AID, xiQr, ec).real == TatePairing.computeF(TatePairing, A1, Qr, ec).real
    print('Valid sender/car          =', validSender)
    A2_P = TatePairing.computeF(TatePairing, A2, P, ec)
    AID_gammaP = TatePairing.computeF(TatePairing, AID, gammaP, ec)
    msg_point_bP = TatePairing.computeF(TatePairing, msg_point, bP, ec)
    validMsg = A2_P.real == AID_gammaP.real * msg_point_bP.real
    print('Valid message             =', validMsg)
    ################################# Finding the bad guy #################################
    AID_A3 = TatePairing.computeF(TatePairing, AID, A3, ec)
    AID_A3_inv = HalfComplex.HCpow(HalfComplex, AID_A3, (xi_inv), ec.q)
    print('e(Qv, Qv                  =', AID_A3_inv.toString())
    # print("Iterate throw the BL to find the RID of the bad guy")
    # for i in users:
    #     atQr = ec.mulJ(expA02, xi_inv)
    #     hT = EC.hashTimeToInt(str(sT))
    #     pair1 = TatePairing.computeF(TatePairing, expA01, ec.add2(ec.mulJ(Qr, hT), atQr), ec)
    #     tmpUsercoords = i.split(";")[0].split(" ")
    #     tmpUser = Fp2Point(int(tmpUsercoords[0]), int(tmpUsercoords[1]))
    #     pair2 = TatePairing.computeF(TatePairing, tmpUser, xiQr, ec)
    #     if pair1.real == pair2.real:
    #         print("The bad guy is: " + tmpUser.toString())
    #         blacklist.append(tmpUser.toString())
    #         #             appendToList("params/blacklist", tmpUser.toString())
    #         break
    stop = timeit.default_timer()
    print('Time of MALICIOUS (min. 7 x TatePairing, 6 x multiplication with scalar, 1 x modInverse, 2 x hash):',
          stop - start)
    print()


#     main()


################################# SAVE & GENERATE #################################
def savePoint(fileName, point):
    """
    Generált pontok mentése fájlba
    :param fileName: fájlnév;
    :param point: pont;
    """
    with open(fileName, 'w') as filehandle:
        filehandle.write(str(point.x) + "\n")
        filehandle.write(str(point.y) + "\n")
        filehandle.close()


def saveConstant(fileName, constant):
    """
    Konstans mentése fájlba
    :param fileName: fájlnév;
    :param constant: konstans;
    """
    with open(fileName, 'w') as filehandle:
        filehandle.write(str(constant) + "\n")
        filehandle.close()


def appendToList(fileName, string):
    """
    Tárolt lista bővítése
    :param fileName: fájlnév;
    :param string: a hozzáadni kívánt felhasználó stringként;
    """
    with open(fileName, 'a+') as filehandle:
        filehandle.write(string + "\n")
        filehandle.close()


def genUsers():
    """A teszteléshez szükséges fiktív felhasználók listájának létrehozása és mentése fájlba"""
    with open('params/users', 'w') as filehandle:
        filehandle.write('')
        filehandle.close()
    for i in range(0, 99):  # @UnusedVariable
        ecPoint = ec.at_gen(None)
        tmpUser = HalfComplex.HCpow(HalfComplex, Fp2Element(ecPoint.x, ecPoint.y), random.getrandbits(30), ec.q)
        users.append(tmpUser.toString())
        appendToList('params/users', tmpUser.toString())


def genBlacklist():
    """A teszteléshez szükséges fiktív rosszindulatú felhasználók listájának létrehozása és mentése fájlba"""
    with open('params/blacklist', 'w') as filehandle:
        filehandle.write('')
        filehandle.close()
    for i in range(0, 99):  # @UnusedVariable
        tmpUser = ec.at_gen(None)
        appendToList('params/blacklist', tmpUser.toString())


################################# Pairing tests #################################
def pairing(testcase=0):
    """Tate párosítás tesztelése"""
    # tmp1 = ec.at(None)
    # tmp2 = ec.at(None)
    # a = random.getrandbits(30)
    # T = random.getrandbits(30)
    # pair1 = TatePairing.computeF(TatePairing, tmp1, tmp2, ec)
    # print('e(P,Q):    ', pair1.toString())
    # print('e(P, 2Q):  ', TatePairing.computeF(TatePairing, tmp1, ec.mulJ(tmp2, 2), ec).toString())
    # print('e(2P, Q):  ', TatePairing.computeF(TatePairing, ec.mulJ(tmp1, 2), tmp2, ec).toString())
    # print('e(P, Q)^2: ', HalfComplex.HalfComplex.HCpow(HalfComplex, pair1, 2, ec.q).toString())
    #
    # pair2 = TatePairing.computeF(TatePairing, Qv, gammaQr, ec)
    # pair3 = TatePairing.computeF(TatePairing, Qr, gammaQv, ec)
    # print(pair2.real == pair3.real)

    if testcase == 1:
        timeCounter = 0
        for i in range(0, 100):  # @UnusedVariable
            tmp1 = ec.at(None)
            tmp2 = ec.at(None)
            start = timeit.default_timer()
            pair1 = TatePairing.computeF(TatePairing, tmp1, tmp2, ec)
            print('Tate bilinear pair1:', pair1.toString())
            stop = timeit.default_timer()
            timeCounter += stop - start
        print(timeCounter / 100)
    # main()


################################# PERFORMANCE TESTS #################################
def performanceTest(testcase=""):
    """Teljesítmény analízis tesztesetek"""
    #     PAIRING
    if testcase == "pairing":
        timeCounter = 0
        for i in range(0, 100):  # @UnusedVariable
            tmp1 = ec.at(None)
            tmp2 = ec.at(None)
            start = timeit.default_timer()
            pair1 = TatePairing.computeF(TatePairing, tmp1, tmp2, ec)
            stop = timeit.default_timer()
            timeCounter += stop - start
        print('Time of pairing', timeCounter / 100)
    #     MULTIPLICATION
    if testcase == "multiply":
        count = 0
        for x in range(0, 100):
            tmp1 = ec.at(None)
            x = random.getrandbits(128)
            start = timeit.default_timer()
            tmp2 = ec.mulJ(tmp1, x)
            stop = timeit.default_timer()
            count += stop - start

        print('Time of multiplication: ', count / 100)
    #     EXPONENTIAL
    if testcase == "exp":
        timeCounter = 0
        for i in range(0, 100):  # @UnusedVariable
            tmp1 = ec.at(None)
            tmp2 = ec.at(None)
            pair1 = TatePairing.computeF(TatePairing, tmp1, tmp2, ec)
            exp = random.getrandbits(128)
            start = timeit.default_timer()
            pow(pair1.real, exp, ec.q)
            stop = timeit.default_timer()
            timeCounter += stop - start
        print('Time of exp. pairing', timeCounter / 100)
    #     HASH
    if testcase == "hash":
        timeCounter = 0
        for i in range(0, 100):
            tmp1 = ec.at(None)
            hash_def = hashlib.sha256()
            hash_def.update(tmp1.toString().encode())
            start = timeit.default_timer()
            hash_def.hexdigest()
            stop = timeit.default_timer()
            timeCounter += stop - start
        print('Time of hash', timeCounter / 100)
    #     Symmetric Encryption
    if testcase == "symEnc":
        timeCounter = 0
        key = 'abcdefghijklmnop'
        text = 'TechTutorialsX!!TechTutorialsX!!'
        text = text.encode()
        for i in range(0, 100):  # @UnusedVariable
            start = timeit.default_timer()
            cipher = AES.new(key.encode(), AES.MODE_ECB)
            msg = cipher.encrypt(text)
            stop = timeit.default_timer()
            timeCounter += stop - start
        print('Time of symmetric encryption', timeCounter / 100)
    #     MAC
    if testcase == "HMAC":
        timeCounter = 0
        for i in range(0, 100):  # @UnusedVariable
            update_bytes = ec.at(None).toString().encode()
            password = b'abcde1234'
            start = timeit.default_timer()
            my_hmac = hmac.new(update_bytes, password, hashlib.md5)  # Create hash using md5 algorithm
            stop = timeit.default_timer()
            timeCounter += stop - start

        print('Time of HMAC', timeCounter / 100)


def test():
    ec = EC.EC()
    a = random.getrandbits(30)
    xi = random.getrandbits(30)
    b = random.getrandbits(30)
    msg = ec.at("kamu")
    aQv = ec.mulJ(Qv, a)
    axiQv = ec.mulJ(aQv, xi)
    bP = ec.mulJ(P, b)
    agQv = ec.mulJ(gammaQv, a)
    bHash = ec.mulJ(msg, b)
    A2 = ec.add2(agQv, bHash)
    pair1 = TatePairing.compute(TatePairing, A2, P, ec)
    pair2 = TatePairing.computeF(TatePairing, aQv, gammaP, ec)
    pair3 = TatePairing.computeF(TatePairing, msg, bP, ec)
    print(pair1.real)
    print(pair2.real)
    print(pair3.real)
    print(pair2.real * pair3.real)

    print("Complex pow:" + Complex.complexPow(Fp2Element(0, 1), 3, ec).toString())


def testPow():
    print("P: " + P.toString())
    print("Qv: " + Qv.toString())
    print("################# Compressed TatePairing #################")
    print("TatePairing (P, Qv)  : " + TatePairing.computeF(TatePairing, P, Qv, ec).toString())
    print("TatePairing (Qv, P)  : " + TatePairing.computeF(TatePairing, Qv, P, ec).toString())
    print("TatePairing (2P, Qv) : " + TatePairing.computeF(TatePairing, ec.mulJ(P, 2), Qv, ec).toString())
    print("TatePairing (P, Qv)^2: " + HalfComplex.HCpow(HalfComplex, TatePairing.computeF(TatePairing, P, Qv, ec), 2, ec.q).toString())
    print("################# TatePairing #################")
    print("TatePairing (P, Qv)  : " + TatePairing.compute(TatePairing, P, Qv, ec).toString())
    print("TatePairing (Qv, P)  : " + TatePairing.compute(TatePairing, Qv, P, ec).toString())
    print("TatePairing (2P, Qv) : " + TatePairing.compute(TatePairing, ec.mulJ(P, 2), Qv, ec).toString())
    print("TatePairing (P, Qv)^2: " + Complex.complexPow(TatePairing.compute(TatePairing, P, Qv, ec), 2, ec).toString())

def ecdsa():
    timeCounter = 0
    for i in range(0, 100):  # @UnusedVariable
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.verifying_key
        vk.precompute()
        signature = sk.sign(b"message")
        start = timeit.default_timer()
        assert vk.verify(signature, b"message")
        stop = timeit.default_timer()
        timeCounter += stop - start
    print('Time of ECDSA', timeCounter / 100)

################################# MAIN #################################
if __name__ == "__main__":
    """Main"""
    init()
    # main()
    # setup()
    # incident()
    # exposure()
    # pairing(1)
    performanceTest("pairing")
    # testPow()
    ecdsa()
