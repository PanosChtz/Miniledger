from zksk import Secret, DLRep
from zksk import utils
from zksk.composition import OrProofStmt
from zksk.primitives.rangeproof import RangeStmt
from petlib.ec import EcGroup, Bn
from time import process_time 
from itertools import count
import hashlib
from merklelib import MerkleTree
import miller_rabin
import numpy
import sys 

class PublicParams:
    """
    Represents system's public parameters
    ...
    Attributes
    ----------
    group : EcGroup
        Elliptic curve as defined in petlib library
    g : EcPt
        First generator g
    h : EcPt
        Second generator h
    """
    group = EcGroup(714) #SECG curve over a 256 bit primefield ("secp256k1")
    def __init__(self, g = group.hash_to_point(b"g"),h = group.hash_to_point(b"h")):
        """
        Parameters
        ----------
        g : EcPt
            First generator g
        h : EcPt
            Second generator h
        """
        self.g = g
        self.h = h

sys.setrecursionlimit(10**6)
PP = PublicParams()
TABLERANGE = 1000 #range of valid values

#modulo for RSA accumulator
N = Bn.from_decimal("""
4032089980897905213962056073493273993829636268407162189353455148380250
27287317766031638176704649012201503430487420497370587817122236795937514515413500067
89237077650550373179063781526130646276325878585433387170982310141316725833705053827
70595120708149217970611509153585488043115239061679914235986788004977306591979160122
75212555813670970265117359389245890418085039904355549130347106429599536045855082720
16469642627142938754714690046879700679673435520051797662356790442468789780956391865
31026325146262255230626466636429839665014613232522991039354805076329663152642153027
76176610757299593835447511972979217804822997308905778667884670106029130358967195668
43378519725241144911964028703874065604060863201053821165185672754305830174344524517
48753203235175990273284937295190284014811919108501772131485389621808636020583509071
61642096083833133867288717212215238943687346068974328678630478688227900820380159353
5370332782878399545240317""".replace("\n", ""))


class Bank:
    """
    Represents a Bank

    Attributes
    ----------
    ids : count
        Counter for id
    id : int
        A unique identifier for a Bank
    sk : Secret
        Bank's secret key
    pk : EcPt
        Bank's public key
    """
    _ids = count(0)
    def __init__(self, sk = None, pk = None):
        """
        id : int
            A unique identifier for a Bank
        sk : Secret
            Bank's secret key
        pk : EcPt
            Bank's public key
        """
        self.id = next(self._ids)
        self.sk = Secret(PP.group.order().random())
        self.pk = self.sk.value*PP.h

class MiniCell:
    """
    Represents a MiniLedger cell
    Attributes
    ----------
    cipher : tuple
        Twisted Elgamal ciphertexts tuple
    cm : EcPt
        Auxiliary commitment
    piAC : OrProof
        NIZK for piAC
    D : ----
        Pruning digest
    Q : list
        Running total in Twisted Elgamal format, initialized to zero
    """
    def __init__(self,cipher, cm = None, piAC = None, D = None, Q = None):
        """
        cipher : tuple
            Twisted Elgamal ciphertexts tuple
        cm : EcPt
            Auxiliary commitment
        piAC : OrProof
            NIZK for piAC
        D : ----
            Pruning digest
        Q : list
            Running total, initialized to zero
        """
        self.cipher = cipher
        self.cm = cm
        self.piAC = piAC
        self.D = D
        self.Q = Q 

class MiniColumn:
    """
    Represents a MiniLedger column
    Attributes
    ----------
    ids : count
        Counter for id
    id : int
        A unique identifier for a column
    bank : Bank
        The Bank represented in the column
    cells : list
        List of MiniCell objects
    """
    _ids = count(0)
    def __init__(self,bank = None,cells = None):
        """
        id : int
            A unique identifier for a column
        bank : Bank
            The Bank represented in the column
        cells : list
            List of MiniCell objects
        """
        self.id = next(self._ids)
        self.bank = Bank()
        self.cells = []

class OrProof:
    """
    Represents a disjunctive ZK proof
    Attributes
    ----------
    stmt : OrProofStmt
        The proof statement using zksk lib
    nizk : NIZK
        NIZK proof of statement using zksk lib
    """
    def __init__(self,stmt = None,nizk = None):
        """
        stmt : OrProofStmt
            The proof statement using zksk lib
        nizk : NIZK
            NIZK proof of statement using zksk lib
        """
        self.stmt = stmt
        self.nizk = nizk

def lookupTable():
    """Creates a lookup table to decrypt values
    Parameters
    ----------
    TABLERANGE : int
        Global variable that set system's valid values
    Returns
    -------
    list
        A list of values that correspond from -TABLERANGE to +TABLERANGE
    """    
    table = []
    for i in range(-TABLERANGE, TABLERANGE+1):
        table.append(i*PP.g)
    return table

#start_table = time.time()
TABLE = lookupTable() #precompute lookup table for decrypting values
#end_table = time.time()
#print("Lookup table compute time: " + str( round( (end_table - start_table)*1e3 ,3) ) + "ms")

def twistEncrypt(pk,m,randomness = None):
    """Encrypts using Twisted ElGamal scheme
    Parameters
    ----------
    pk : EcPt
        Encryption public key
    m : int
        Plaintext
    randomness : Secret
        Optional predefined randomness
    Returns
    -------
    tuple
        A tuple of 2 Twisted ElGamal ciphertexts
    """    
    if randomness == None:
        r = Secret(value=PP.group.order().random())
    else:
        r = randomness
    cipher1 = r.value*pk
    cipher2 = m*PP.g + r.value*PP.h
    return (cipher1,cipher2)

def twistDecrypt(sk,ctuple,lookupTable):
    """Decrypts using Twisted ElGamal scheme
    Parameters
    ----------
    sk : Secret
        Decryption secret key
    ctuple : tuple
        A tuple of 2 Twisted ElGamal ciphertexts
    lookupTable : list
        Lookup Table to recover message
    TABLERANGE : int
        Global variable that set system's valid values
    Returns
    -------
    int
        The index in the lookupTable for the decrypted big number

    Example:
        Decrypt value in cell (0,1) of L
        >>> twistDecrypt(L[0].bank.sk, L[0].cells[1].cipher,TABLE)
    """   
    gm = ctuple[1] - sk.value.mod_inverse(m = PP.group.order())*ctuple[0]
    return (lookupTable.index(gm) - TABLERANGE)

def columnProd(ledger,column):
    """Computes a column's Twisted ElGamal ciphertext products (deprecated)
    Parameters
    ----------
    ledger : list
        Ledger
    column : int
        Index of ledger's column
    Returns
    -------
    list
        A list of 2 Twisted ElGamal ciphertexts
    """
    cipher_prod = [PP.group.infinite(),PP.group.infinite()] #(c1,c2)
    for i in ledger[column].cells:
        cipher_prod = [cipher_prod[0] + i.cipher[0] + i.Q[0], cipher_prod[1] + i.cipher[1] + i.Q[1] ] #mod?
    return cipher_prod

def runningTotal(column):
    """Iteratively maintains a column's running total in Twisted ElGamal ciphertexts, based on the previous ones
    Parameters
    ----------
    column : MiniColumn
        A Ledger's column
    Returns
    -------
    list
        A list of 2 Twisted ElGamal ciphertexts
    """
    cipher_prod = [PP.group.infinite(),PP.group.infinite()] #(c1,c2)
    if len(column.cells) != 0:
        cipher_prod = [cipher_prod[0] + column.cells[-1].Q[0], cipher_prod[1] + column.cells[-1].Q[1] ] #mod?
        #Add previous cell running total
    return cipher_prod

def MakeLedger(n):
    """Instantiates MiniLedger
    Parameters
    ----------
    n : int
        A Ledger's size (in columns)
    Returns
    -------
    list
        A list of MiniColumn objects
    """
    newLedger = list(map(lambda x: MiniColumn(), range(n)))
    return (newLedger)

def createTx(ledger,valuearray,initialize = False):
    """Creates a MiniLedger transaction and appends it to ledger (appends one MiniCell on each MiniColumn)
    Parameters
    ----------
    ledger : list
        Ledger
    valuearray : list
        A list of values, representing transaction senders, receivers and amounts. Does not check for balance!
    initialize : bool
        If True, creates special initialization transaction without proof elements
    Returns
    -------
    None

    Example:
        Transfer value of 1 from Bank 0 to Bank 2 on ledger L
        >>> createTx(L,[-1,0,1])
    """
    if len(ledger) == len(valuearray):
        randomsum = Bn(0) # sum of randomness
        ledger_size = len(ledger) - 1
        for i,colmn in enumerate(ledger):
            #r
            if i == ledger_size:
                rand = Secret(value=PP.group.order().mod_sub(randomsum,PP.group.order())) #find remainder randomness
            else:
                rand = Secret(value=PP.group.order().random())
            #v
            v = Secret(value=valuearray[i])
            #(c1,c2)
            ciphers = twistEncrypt(colmn.bank.pk,valuearray[i],rand)
            #(c1_hat,c2_hat)
            runTot = [a+b for a,b in zip(ciphers,runningTotal(colmn))]
            #r_prime
            rand_prime = Secret(value=PP.group.order().random())
            #cm and NIZKs
            piACproof = None #if initializing ledger
            cmAux = None
            if not initialize:
                if valuearray[i] >= 0:
                    #if receiving, cm = v*g + r_prime * h
                    cmAux = valuearray[i]*PP.g + rand_prime.value*PP.h
                    stmt1 = DLRep(cmAux, v * PP.g + rand_prime * PP.h) & DLRep(ciphers[1], v * PP.g + rand * PP.h) & DLRep(ciphers[0], rand*colmn.bank.pk) & RangeStmt(cmAux,PP.g,PP.h,0,TABLERANGE,v,rand_prime)
                    stmt2 = DLRep(cmAux, rand*PP.g + rand_prime*PP.h) & DLRep(runTot[1],rand*PP.g + rand*runTot[0]) & DLRep(ciphers[1], v * PP.g + rand * PP.h) & DLRep(ciphers[0], rand*colmn.bank.pk) & DLRep(colmn.bank.pk, rand*PP.h)
                    stmt2.set_simulated()
                else:
                    #if spending, find v_hat from c2_hat
                    totalAssets = twistDecrypt(colmn.bank.sk,runTot,TABLE)
                    v_hat = Secret(value=totalAssets)
                    #set cm = v_hat*g + r_prime * h
                    cmAux = totalAssets*PP.g + rand_prime.value*PP.h
                    stmt1 = DLRep(cmAux, v * PP.g + rand_prime * PP.h) & DLRep(ciphers[1], v * PP.g + rand * PP.h) & DLRep(ciphers[0], rand*colmn.bank.pk) 
                    stmt2 = DLRep(cmAux, v_hat*PP.g + rand_prime*PP.h) & DLRep(runTot[1],v_hat*PP.g + Secret(value=colmn.bank.sk.value.mod_inverse(m = PP.group.order()))*runTot[0]) & DLRep(ciphers[1], v * PP.g + rand * PP.h) & DLRep(ciphers[0], rand*colmn.bank.pk) & DLRep(colmn.bank.pk, colmn.bank.sk*PP.h) & RangeStmt(cmAux,PP.g,PP.h,0,TABLERANGE,v_hat,rand_prime)
                    stmt1.set_simulated()
                #construct ZKP piAC
                #Witnesses: 
                #v = valuearray[i]
                #r = rand
                #r' = rand_prime
                #v_hat = totalAssets
                #sk = colmn.bank.sk
                #Public information:
                #pk = colmn.bank.pk
                #cm = cmAux
                #(c1,c2) = ciphers
                #c2_hat = runTot
                or_stmt = OrProofStmt(stmt1, stmt2)
                #rangeprf = RangeStmt(cmAux,PP.g,PP.h,0,TABLERANGE,rand_prime)
                #nizk = or_stmt.prove() #piAC
                piACproof = OrProof(or_stmt,or_stmt.prove())
            colmn.cells.append(MiniCell(ciphers,cmAux,piACproof,None,runTot))
            randomsum = randomsum.mod_add(rand.value,PP.group.order()) #add randomness mod grp order
    #twistDecrypt(L[9].bank.sk,L[9].cells[0].cipher,table)            

def piBverify(ledger,row):
    """Verifies balance on a ledger row
    Parameters
    ----------
    ledger : list
        Ledger
    row : int
        Ledger's row.
    Returns
    -------
    bool
        Verification result
    Example:
        >>> piBverify(L,0) #Typically evaluates to False for initialization row!
    """
    #verifies value balance for a transaction on a ledger row
    pt = PP.group.infinite()
    for colmn in ledger:
        pt = pt + colmn.cells[row].cipher[1]
    return (pt == PP.group.infinite())

def piACverify(column,i):
    """Verifies NIZK on a ledger cell
    Parameters
    ----------
    column : MiniColumn
        A Ledger's column
    i : int
        Column's index.
    Returns
    -------
    bool
        Verification result
    Example:
        >>> piACverify(L[0],1) #Typically evaluates to False for initialization row!
    """
    proofstatement = column.cells[i].piAC.stmt
    check = proofstatement.verify(column.cells[i].piAC.nizk)
    return check

def runningTotalVrfy(column):
    return 0

def decryptRow(ledger,row):
    """Decrypts values in a whole ledger row (in 'god' mode knowing all sk's - inverse of createTx)
    Parameters
    ----------
    ledger : list
        Ledger
    row : int
        Ledger's row.
    Returns
    -------
    list
        A list of values, representing transaction senders, receivers and amounts.
    Example:
        >>> decryptRow(L,1)
    """
    outList = []
    for colmn in ledger:
        outList.append(twistDecrypt(colmn.bank.sk,colmn.cells[row].Q,TABLE))
    return outList

def verifyRow(ledger,row):
    """Verifies all NIZK on a ledger row
    Parameters
    ----------
    ledger : list
        Ledger
    row : int
        Ledger's row.
    Returns
    -------
    bool
        Verification result, evaluates to False if any NIZK does not verify
    Example:
        >>> verifyRow(L,1)
    """
    out = True
    for colmn in ledger:
        out = out and piACverify(colmn,row)
    return out

def auditTx(column,i):
    """Audits a transaction on a ledger cell
    Parameters
    ----------
    column : MiniColumn
        A Ledger's column
    i : int
        Column's index.
    Returns
    -------
    bool
        Audit result
    Example:
        >>> auditTx(L[0],1) #Should always evaluate to True
    """
    #Bank first decrypts value
    v = twistDecrypt(column.bank.sk, column.cells[i].cipher,TABLE)
    #construct audit NIZK pi^Aud
    #c1 = colmumn.cells[i].cipher[0]
    #c2 = colmumn.cells[i].cipher[1]
    stmt = DLRep(column.cells[i].cipher[1] - v * PP.g, Secret(value=column.bank.sk.value.mod_inverse(m = PP.group.order())) * column.cells[i].cipher[0])
    nizk = stmt.prove() #sk doesn't need to be supplied since it's set in a Secret() constructor.
    check = stmt.verify(nizk)
    return check

def h(preimage):
    """Hashes a byte array using SHA256
    ----------
    preimange : bytes
        Hash function input
    Returns
    -------
    str
        SHA256 digest.
    Example:
        >>> a = pruneMerkle(L[0])
    """
    return hashlib.sha256(preimage).hexdigest()

def pruneMerkle(column,depth=None):
    """Prunes using Merkle Tree
    ----------
    column : MiniColumn
        A Ledger's column
    depth : int
        The pruning depth (starting from first element)
    Returns
    -------
    list
        A list containing 
        [0] the pruned elements
        [1] the Merkle tree
        [2] the performance timer in msec
    Example:
        >>> a = pruneMerkle(L[0])
    """
    privateList = []
    if (depth==None):
        depth = len(column.cells)
    for i,cell in enumerate(column.cells):
        if i >= depth:
            break
        #retrieve (i + c1 + c2) in bytes for each row. Byte length 1 + 33 + 33 = 67
        #index redundant as Merkle tree is also position binding
        privateList.append(bytes(str(i),"utf8")+cell.cipher[0].export()+cell.cipher[1].export())
    starttime = process_time()
    mtree = MerkleTree(privateList,h)
    endtime = process_time()
    #proof = tree.get_proof(h(pruneList[0]))
    #tree.verify_leaf_inclusion(pruneList[0],proof)
    return [privateList,mtree,round( (endtime - starttime)*1e3 ,3)]

def proveMerkle(privateList,mtree,i):
    """Proves membership in a Merkle Tree
    ----------
    privateList : list
        A list of pruned elements
    mtree : MerkleTree
        The merkle tree
    i : int
        The item's index
    Returns
    -------
    AuditProof
        A Merkle proof of membership.
    Example:
        >>> proof = proveMerkle(a[0],a[1],0)
    """
    return mtree.get_proof(privateList[i])

def verifyMerkle(mtree,proof,element):
    """Verifies membership in a Merkle Tree
    ----------
    mtree : MerkleTree
        The merkle tree
    proof : AuditProof
        A Merkle proof of membership
    element : bytes
        The element proven
    Returns
    -------
    bool
        Verification result
    Example:
        >>> verifyMerkle(a[1],proof,a[0][0])
    """
    return mtree.verify_leaf_inclusion(element,proof)

def ecPt2Int(point):
    """Maps an EC point to an integer
    ----------
    point : EcPt
        An EC point
    Returns
    -------
    int
        The integer mapping to the EC point.
    """
    return int(h(point.export()),16)

def hashToPrime(number):
    """Maps an integer to a prime number using a hash function
    ----------
    number : int
        An integer
    Returns
    -------
    int
        The mapped prime number.
    """
    #convert integer to bytes
    newhash = h(number.to_bytes((number.bit_length()+7)//8, byteorder = 'big'))
    if int(newhash[63],16) % 2 == 0:
        #if hash is even, xor LSB to make it odd
        newhash = newhash[0:63] + str(int(newhash[63],16) ^1)
    x = int(newhash,16)
    if miller_rabin.miller_rabin(x,20):
        #Check if prime
        #maybe replace with Bn.is_prime() ?
        return x
    else:
        return hashToPrime(x)

def pruneRSA(column,depth=None):
    """Prunes using RSA Accumulator
    ----------
    column : MiniColumn
        A Ledger's column
    depth : int
        The pruning depth (starting from first element)
    Returns
    -------
    list
        A list containing: 
        [0] the pruned elements (kept private)
        [1] the respective primes (cached)
        [2] the accumulator value
        [3] the performance timer in msec
    Example:
        >>> a = pruneRSA(L[0])
    
    """
    privateList = []
    primeList = []
    acc = Bn(3) #generator g
    if (depth==None):
        depth = len(column.cells)
    starttime = process_time()
    for i,cell in enumerate(column.cells):
        if i >= depth:
            break
        #append row index i and (c1,c2) to list
        #privateList.append([i,cell.cipher])
        privateList.append(cell.cipher)
        #convert EC points to integers, add with index and compute hash to prime
        primeList.append(hashToPrime(i + ecPt2Int(cell.cipher[0]) + ecPt2Int(cell.cipher[1])))
    #compute product of all primes
    primeProduct = numpy.prod(primeList)
    #add prime product to accumulator
    acc = acc.pow(Bn.from_decimal(str(primeProduct)),N)
    endtime = process_time()
    return [privateList,primeList,acc,round( (endtime - starttime)*1e3 ,3)]

def proveRSA(privateList,primeList,iList):
    """Proves membership in an RSA Accumulator
    ----------
    privateList : list
        A list of pruned elements
    primeList : List
        A list of primes matching elements (optional, can be recomputed)
    i : list
        A list of indices (can batch)
    Returns
    -------
    list
        A list containing:
        [0] list of elements requested to prove membership
        [1] membership witness
        [2] the performance timer in msec
    Example:
        >>> b = proveRSA(a[0],a[1],[0,1])
    """
    acc = Bn(3) #generator g
    #fetch elements requested
    proveList = list( privateList[i] for i in iList)
    #compute witness for those elements (primes not from queried elements)
    prodlist = [item for item in primeList if item not in list( primeList[i] for i in iList)]
    starttime = process_time()
    #primeprod = numpy.prod([item for item in primeList if item not in list( primeList[i] for i in iList)])
    primeprod = numpy.prod(prodlist)
    witness = acc.pow(Bn.from_decimal(str(primeprod)),N)
    endtime = process_time()
    #prPrimeProduct = numpy.prod(list( primeList[i] for i in iList))
    return [proveList,witness,round( (endtime - starttime)*1e3 ,3)]

def verifyRSA(acc,witness,proveList,iList):
    """Verifies membership in an RSA Accumulator
    ----------
    acc : petlib.bn.Bn
        The accumulator value
    witness : petlib.bn.Bn
        The witness
    proveList : list
        A list of pruned elements to be proven membership
    i : list
        A list of indices (can batch)
    Returns
    -------
    bool
        Verification result
    Example:
        >>> verifyRSA(a[2],b[1],b[0],[0,1])
    """
    primeProd = 1
    #compute prime product for elements to be verified membership
    for i,cell in zip(iList,proveList):
        primeProd = primeProd * hashToPrime(i + ecPt2Int(cell[0]) + ecPt2Int(cell[1]))
    #return acc == Bn(3).pow(Bn.from_decimal(str(witness*primeProd)),N)
    return acc == witness.pow(Bn.from_decimal(str(primeProd)),N)

'''
#Sample run:
L = MakeLedger(10)
createTx(L,[100,100,100,100,100,100,100,100,100,100],True)
print("Initialization row " + str(decryptRow(L,0)))
createTx(L,[-5,0,0,0,0,0,0,0,0,5])
print("Values after first tx: " + str(decryptRow(L,1)))
print("NIZK piAC: " + str(verifyRow(L,1)))
print("piB: " + str(piBverify(L,1)))
createTx(L,[-15,0,0,0,0,0,0,0,15,0])
createTx(L,[0,0,0,0,0,0,0,0,-15,15])
'''
#Will throw an error because of not enough assets
#createTx(L,[-96,0,0,0,0,0,0,0,0,96])

#L = MakeLedger(2)
#createTx(L,[-5,5])
