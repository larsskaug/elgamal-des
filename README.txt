ElGamal
Assignment #3 for CIS6370 Computer Data Security
This library uses java.security and BouncyCastleProvider but only to provide a generator, aka primitive element.

The code includes both Fermat and Miller-Rabin tests for primality, although only the latter is executed.

The method to square and multiply is written in a recursive functional way, the rest of the program is procedural.

How to Run
The program will run in a command line environment and requires Java to be installed.

Provide two arguments to run

A key size in bits (e.g. 256)
An integer serving as the message
Example:

java -jar target/scala-2.13/elgamal-assembly-0.0.1.jar 256 999999999999999999

Example output:

Random number generated (which should be prime): 109373364019191846518792159822877499545260235315870931821216399442029945139367
p is indeed a prime
generator (alpha): 58977229791341236446612311927516290523346657244704001990135008980926808464775
Value of a: 91413579509604329193660354269043832434824920584598825142275802321675692704911
Alpha to the Power of a: 36777149910593089700611654103673031469042789522314444777611217712183228797397
Public key (p, alpha, a): (109373364019191846518792159822877499545260235315870931821216399442029945139367, 58977229791341236446612311927516290523346657244704001990135008980926808464775, 36777149910593089700611654103673031469042789522314444777611217712183228797397)
decrypted: 999999999999999999