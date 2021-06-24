# Miniledger

This is a proof-of-concept implementation for MiniLedger (https://eprint.iacr.org/2021/869). It does *not* include consensus and network layers. Code is for educational purposes only, and not for production use.

## System requirements and dependencies
- Ubuntu 18.04 LTS or above (Mac - Windows systems not tested or supported)
- Python 3.6 and above
```
pip3 install petlib
pip3 install git+https://github.com/spring-epfl/zksk
pip3 install merklelib
pip3 install miller_rabin
pip3 install numpy
```
## Sample run

```
L = MakeLedger(10)
createTx(L,[100,100,100,100,100,100,100,100,100,100],True)
print("Initialization row " + str(decryptRow(L,0)))
createTx(L,[-5,0,0,0,0,0,0,0,0,5])
print("Values after first tx: " + str(decryptRow(L,1)))
print("NIZK piAC: " + str(verifyRow(L,1)))
print("piB: " + str(piBverify(L,1)))
createTx(L,[-15,0,0,0,0,0,0,0,15,0])
createTx(L,[0,0,0,0,0,0,0,0,-15,15])
```
Will throw an error because of not enough assets:
```
createTx(L,[-96,0,0,0,0,0,0,0,0,96])
```
