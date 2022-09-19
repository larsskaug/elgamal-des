## Hybrid Encryption with ElGamal and DES 
# Course Project for CIS6370 Computer Data Security

This solution is written in Scala and contains two classes: ElGamal and Des. 
The structure of the code is really simple. There is a main object that instantiates the two classes listed 
above for the execution. 

The code runs on the command line and returns details of how the encryption is put together.

# ElGamal
ElGamal is used for the public, aka asymmetric, encryption. 
`java.security` and `BouncyCastleProvider` are uesed but only to provide a generator, aka primitive element.

The code includes both Fermat and Miller-Rabin tests for primality, although only the latter is executed.

The method to square and multiply is written in a recursive functional way, the rest of the program is procedural.

# DES
Only two methods from the Des class are used in the main method, one for encryption and another for decryption.


# Limitations
This code does not contain much error checking and has not been heavily tested. 

# How to Run

The program will run in a command line environment and requires Java to be installed.

Provide two arguments to run
1. A key size in bits (e.g. 256)
2. An integer serving as the message
3. A Message to encrypt and decrypt with DES

Example:

`java -jar target/scala-2.12/ElGamal+DES.jar 256 12302436806434409693 BAAAAAAAAAAAAAAA`

Example output:

```
#################################################################################################
Assymmetric encryption with ElGamal first
#################################################################################################

Random number generated (which should be prime): b9b3740fe9a95e41020b718a5542059097dec35e4be6bc7e6bd89cf0abee6e0f
Miller-Rabin confirms that p is a Prime
Generator (alpha): 26bfc47f8fc08f86956bf402adc6a35ce107034bafb95da626e7da04541e323e
Value of a: 5937fa77ea27979ea47a2017edf5328bf5de149b64f0e5a40a2d0cb1d8d8330c
Alpha to the Power of a: b189b467b23feb97c8dd28f6cca24b5f8f3d8f916fbff6c34dfd1f62bad818b0
Public key (p, alpha, a):
(b9b3740fe9a95e41020b718a5542059097dec35e4be6bc7e6bd89cf0abee6e0f,
26bfc47f8fc08f86956bf402adc6a35ce107034bafb95da626e7da04541e323e,
b189b467b23feb97c8dd28f6cca24b5f8f3d8f916fbff6c34dfd1f62bad818b0)

The key you provided, 12302436806434409693 is encrypted as
cipher (2d369d4a5fe574ac1e826bb3c73bebf6a75c4135e267d73da712188a2b1866ba11f66d5f7d428844, 75245080369068889154640168733219601294359045434159310174276202385079056469451)

A recipient would use the public key listed above to decrypt the cipher to 12302436806434409693
#################################################################################################
Symmetric encryption with DES next
#################################################################################################

Using key aabb09182736ccdd to encrypt the message BAAAAAAAAAAAAAAA with DES we get the following cipher
372D7ED91E5A2C6D
Which can be decrypted again back to BAAAAAAAAAAAAAAA

```


