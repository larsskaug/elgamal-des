import java.security.{KeyPairGenerator, SecureRandom, Security}
import scala.collection.JavaConverters._
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec
import org.bouncycastle.jce.interfaces.ElGamalPublicKey
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import scala.util.Random

class ElGamal(val keySize: Int, val msg: String) {

  val bc = new BouncyCastleProvider()
  Security.addProvider(bc);

  def createKeyPair(random: SecureRandom, keySize: Int) = {
    val generator = KeyPairGenerator.getInstance("ELGamal", bc)
    generator.initialize(keySize, random)
    generator.generateKeyPair
  }


  /** Borrowed from https://literateprograms.org/miller-rabin_primality_test__scala_.html */
  def miller_rabin_pass(a: BigInt, n: BigInt): Boolean = {
    var d: BigInt = 0
    var s: BigInt = 0
    var a_to_power: BigInt = 0
    var i: Int = 0
    d = n - 1
    s = 0
    while (d % 2 == 0) {
      d >>= 1
      s += 1
    }
    a_to_power = a.modPow(d, n)
    if (a_to_power == 1) {
      return true
    }
    for (i <- 1 to s.intValue) {
      if (a_to_power == n - 1) {
        return true
      }
      a_to_power = (a_to_power * a_to_power) % n
    }
    return (a_to_power == n - 1)
  }

  def miller_rabin(n: BigInt): Boolean = {
    var k: Int = 20
    for (i: Int <- 1 to k) {
      var a: BigInt = 0
      var rand: scala.util.Random = new scala.util.Random()
      while (a == 0) {
        a = new BigInt(new java.math.BigInteger("" + (rand.nextDouble() * n.doubleValue).toInt))
      }
      if (!miller_rabin_pass(a, n)) {
        return false
      }
    }
    return true
  }

  // Helper function to make sure a is in range {1,2,3,...,p-2}
  def getRand(p: BigInt, keySize: Int): BigInt = {
    val b = BigInt(keySize, scala.util.Random)
    if (b > BigInt("0") && b < p - BigInt("2")) b
    else getRand(p, keySize)
  }

  val zero = BigInt("0")
  val one = BigInt("1")

  def squareAndMultiply(a: BigInt, k: BigInt, n: BigInt): BigInt = {
    k match {
      case `zero` => `one`
      case `one` => a % n
      case _ => {
        val t_ = squareAndMultiply(a, k/2, n)
        val t = t_.pow(2) % n
        if (k % 2 == 0) t
        else ((a % n) * t) % n
      }
    }
  }

  val random = new SecureRandom();

  val parameterGenerator = new org.bouncycastle.crypto.generators.ElGamalParametersGenerator()
  parameterGenerator.init(keySize,1,random)

  val params = parameterGenerator.generateParameters()

  // 1. Generate a large random prime p
  val p = params.getP

  // Generator (alpha)
  val g = params.getG

  // 2. Select a random integer a
  val a = getRand(p, keySize)

  // Compute alpha to the power of a mod p
  val alphaToPowerOfA = squareAndMultiply(g,a,p)

  val m = BigInt(msg)

  def encrypt(): Map[String,BigInt] = {
    // (c) select k
    val k_ = getRand(p, keySize).toString
    val k = new java.math.BigInteger(k_)
    // (d)
    val gamma = g.modPow(k,p)
    val delta = m * alphaToPowerOfA.modPow(k,p)

    Map("gamma" -> gamma, "delta" -> delta )
  }

  def decrypt(gamma: BigInt, delta: BigInt):BigInt = {
    // (a)
    val p_ = BigInt(p.toString())
    val decrypt_ = gamma.modPow(p_ - BigInt("1") - a, p_)

    // (b)
    val gamma_ = BigDecimal(gamma)
    decrypt_ * delta % p
  }
}

class Des(val text: String, val key: String) {


  // Initial Permutation Table
  val IP = Array(58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)

  // Inverse Initial Permutation Table
  val IP1 = Array(40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)

  // first key-hePermutation Table
  val PC1 = Array(57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)

  // second key-Permutation Table
  val PC2 = Array(14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)

  // Expansion D-box Table
  val EP = Array(32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)

  // Straight Permutation Table
  val P = Array(16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)

  // S-box Table
  val sbox = Array(Array(Array(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7), Array(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8), Array(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0), Array(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)), Array(Array(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10), Array(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5), Array(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15), Array(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)), Array(Array(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8), Array(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1), Array(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7), Array(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)), Array(Array(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15), Array(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9), Array(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4), Array(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)), Array(Array(2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9), Array(14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6), Array(4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14), Array(11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)), Array(Array(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11), Array(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8), Array(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6), Array(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)), Array(Array(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1), Array(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6), Array(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2), Array(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)), Array(Array(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7), Array(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2), Array(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8), Array(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)))
  val shiftBits = Array(1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

  def hexToBin(input: String): String = {
    val b = BigInt(input, 16).toString(2) // Binary
    val pad = "0" * ((input.size * 4) - b.size) // Padding
    pad + b // Prepend padding
      // Much slower: .reverse.padTo(input.length * 4, "0").reverse // left pad
      .mkString
  }

  def binToHex(input: String): String = {
    val b = BigInt(input, 2).toString(16)
    val pad = "0" * ((input.size / 4) - b.size) // Padding
    pad + b // Prepend padding
      .mkString
  }

  def permutation(sequence: Array[Int], input: String): String = {
    val _input = hexToBin(input)
    val output = for (i <- 0 until sequence.length) yield _input.charAt(sequence(i) - 1)
    // same as: 0 to sequence.size -1 map(i => _input.charAt(sequence(i) - 1))

    binToHex(output.mkString)
  }

  // left Circular Shifting bits
  def leftCircularShift(input: String, numBits: Int) = {
    var sz = input.size * 4

    var perm = (for (i <- 0 until sz - 1) yield i + 2) :+ 1 toArray

    def runPermutations(n: Int, res: String): String = {
      if (n > 0) runPermutations(n - 1, permutation(perm, res))
      else res
    }

    runPermutations(numBits, input)
  }

  def getKeys(key: String): Array[String] = {

    def helper(i: Int, key: String, keys: Array[String]): Array[String] = {
      if (i < 16) {
        val k_ = leftCircularShift(key.substring(0, 7), shiftBits(i)) + leftCircularShift(key.substring(7, 14), shiftBits(i))
        helper(i + 1, k_, keys :+ permutation(PC2, k_))
      }
      else keys
    }

    val k = permutation(PC1, key)

    helper(0, k, Array[String]())
  }

  def sBox(input: String): String = {
    var output = ""
    var _input = hexToBin(input)
    var i = 0
    while (i < 48) {
      val temp = _input.substring(i, i + 6)
      val num = i / 6
      val row = Integer.parseInt(temp.charAt(0) + "" + temp.charAt(5), 2)
      val col = Integer.parseInt(temp.substring(1, 5), 2)
      output += Integer.toHexString(sbox(num)(row)(col))

      i += 6
    }
    output
  }


  def xor(a: String, b: String): String = { // hexadecimal to decimal(base 10)
    var t_a = java.lang.Long.parseUnsignedLong(a, 16)
    val t_b = java.lang.Long.parseUnsignedLong(b, 16)
    // xor
    t_a = t_a ^ t_b
    // decimal to hexadecimal
    var a_ = java.lang.Long.toHexString(t_a)
    // prepend 0's to maintain length
    while (a_.length < b.length) a_ = "0" + a_
    a_
  }


  def round(input: String, key: String, num: Int): String = { // fk
    var left = input.substring(0, 8)
    var temp = input.substring(8, 16)
    val right = temp
    // Expansion permutation
    temp = permutation(EP, temp)
    // xor temp and round key
    temp = xor(temp, key)
    // lookup in s-box table
    temp = sBox(temp)
    // Straight D-box
    temp = permutation(P, temp)
    // xor
    left = xor(left, temp)
    //println("Round " + (num + 1) + " " + right.toUpperCase + " " + left.toUpperCase + " " + key.toUpperCase)
    // swapper
    right + left
  }

  def encrypt(text: String, key: String) = {
    val keys = getKeys(key)
    var pText = permutation(IP, text)

    0 to 15 foreach (i => pText = round(pText, keys(i), i))
    pText = pText.substring(8, 16) + pText.substring(0, 8)
    pText = permutation(IP1, pText);
    //println("Ciper text: " + pText.toUpperCase)
    pText.toUpperCase
  }


  def decrypt(text: String, key: String) = {
    val keys = getKeys(key)
    var pText = permutation(IP, text)

    for (i <- 15 to 0 by -1) pText = round(pText, keys(i), 15 - i)
    pText = pText.substring(8, 16) + pText.substring(0, 8)
    pText = permutation(IP1, pText);
    //println("Original text: " + pText.toUpperCase)
    pText.toUpperCase
  }
}


object Main {

  def main(args: Array[String]): Unit = {


    if (args.length != 3) {
      println(
        """Please provide three arguments:
          |(1) A key size in number of bits (e.g. 256) for the Assymetric Portion (ElGamal)
          |(2) An large integer representing the key for the Symmetric encryption (DES)
          |(3) A message for the symmetric encryption
        """.stripMargin)
    }
    else {
      val keySize = args(0).toInt
      val symKey = args(1)
      val elg = new ElGamal(keySize, symKey)

      println(
        """#################################################################################################
          |Assymmetric encryption with ElGamal first
          |#################################################################################################
          |""".stripMargin)

      println("Random number generated (which should be prime): " + elg.p.toString(16))

      // p should be prime, but let's check
      elg.miller_rabin(elg.p) match {
        case true => println("Miller-Rabin confirms that p is a Prime")
        case _ => println("p does not seem to be a prime")
      }

      println("Generator (alpha): " + elg.g.toString(16))
      println("Value of a: " + elg.a.toString(16))

      println("Alpha to the Power of a: " + elg.alphaToPowerOfA.toString(16))

      println(
        s"""Public key (p, alpha, a):
           |(${elg.p.toString(16)},
           |${elg.g.toString(16)},
           |${elg.alphaToPowerOfA.toString(16)})""".stripMargin)

      val encrypted = elg.encrypt()

      println(
        s"""
          |The key you provided, $symKey is encrypted as
          |cipher (${encrypted("delta").toString((16))}, ${encrypted("gamma").toString})
          |""".stripMargin)

      val decryptedElg = elg.decrypt(encrypted("gamma"), encrypted("delta"))

      println(s"""A recipient would use the public key listed above to decrypt the cipher to $decryptedElg""")

      println(
        """#################################################################################################
          |Symmetric encryption with DES next
          |#################################################################################################
          |""".stripMargin)

      val text = args(2) //"AAAAAAAAAAAAAAAAA"
      val key = BigInt(symKey.toString).toString(16) // "AABB09182736CCDD"
      val des = new Des(text, key)


      val desCipher = des.encrypt(text, key)
      val desDecrypt = des.decrypt(desCipher, key)

      println(
        s"""Using key $key to encrypt the message $text with DES we get the following cipher
           |$desCipher
           |Which can be decrypted again back to $desDecrypt
           |""".stripMargin)

    }

  }
}