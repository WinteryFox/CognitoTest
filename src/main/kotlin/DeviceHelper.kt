import com.artify.Hkdf
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


private const val HEX_N = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF")
private val SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG")
private val N = BigInteger(HEX_N, 16)
private val G = BigInteger.valueOf(2)

class DeviceHelper {
    private val a: BigInteger

    private val A: BigInteger

    private val k: BigInteger

    init {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(N.toByteArray())

        var tempa: BigInteger
        var tempA: BigInteger

        do {
            tempa = BigInteger(1024, SECURE_RANDOM).mod(N)
            tempA = G.modPow(tempa, N)
        } while (tempA.mod(N).equals(BigInteger.ZERO))

        a = tempa
        A = tempA

        // k = SHA256_HASH(N + g)
        k = BigInteger(1, hash(N.add(G).toByteArray()))
    }

    private fun hash(vararg input: String, algorithm: String = "SHA-256"): ByteArray =
        hash(input.map { it.toByteArray() }, algorithm)

    private fun hash(vararg input: ByteArray, algorithm: String = "SHA-256"): ByteArray =
        hash(input.toList(), algorithm)

    private fun hash(input: List<ByteArray>, algorithm: String = "SHA-256"): ByteArray {
        val digest = MessageDigest.getInstance(algorithm)
        for (i in input)
            digest.update(i)

        return digest.digest()
    }

    fun secretHash(cognitoClientId: String, email: String, secret: String): String =
        Base64.getEncoder().encodeToString(hmac(secret.toByteArray(), email, cognitoClientId))

    private fun hmac(key: ByteArray, vararg input: String, algorithm: String = "HmacSHA256"): ByteArray =
        hmac(key, input.map { it.toByteArray() }, algorithm)

    private fun hmac(key: ByteArray, vararg input: ByteArray, algorithm: String = "HmacSHA256"): ByteArray =
        hmac(key, input.toList(), algorithm)

    private fun hmac(key: ByteArray, input: List<ByteArray>, algorithm: String = "HmacSHA256"): ByteArray {
        val keySpec = SecretKeySpec(key, algorithm)
        val mac = Mac.getInstance(algorithm)
        mac.init(keySpec)

        for (i in input)
            mac.update(i)

        return mac.doFinal()
    }

    fun passwordClaimSignature(
        deviceGroupKey: String,
        deviceKey: String,
        devicePassword: String,
        srpB: String,
        salt: String,
        timestamp: String,
        secretBlock: String
    ): String {
        val hkdf = deviceAuthenticationKey(deviceGroupKey, deviceKey, devicePassword, srpB, salt)
        val secretBlockDecoded = Base64.getDecoder().decode(secretBlock)
        val signature = hmac(
            hkdf,
            deviceGroupKey.toByteArray(),
            deviceKey.toByteArray(),
            secretBlockDecoded,
            timestamp.toByteArray()
        )

        return Base64.getEncoder().encodeToString(signature)
    }

    fun srpa(): String = HexFormat.of().formatHex(A.toByteArray())

    private fun deviceAuthenticationKey(
        deviceGroupKey: String,
        deviceKey: String,
        devicePassword: String,
        srpB: String,
        salt: String
    ): ByteArray {
        val B = BigInteger(srpB, 16)

        // FULL_PASSWORD = SHA256_HASH(DeviceGroupKey + DeviceKey + ":" + DevicePassword)
        val fullPassword = hash(deviceGroupKey, deviceKey, ":", devicePassword)

        // u = SHA256_HASH(SRP_A + SRP_B)
        val u = BigInteger(1, hash(A.add(B).toByteArray()))
        // x = SHA256_HASH(salt + FULL_PASSWORD)
        val x = BigInteger(1, hash(salt.toByteArray(), fullPassword))

        // S_USER = [ ( SRP_B - [ k * [ (gx) (mod N) ] ] )(a + ux) ](mod N)
        val S = (B.subtract(k.multiply(G.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N)
        // K_USER = SHA256_HASH(S_USER)
        //val K = hash(S.toByteArray())

        val hkdf = Hkdf.getInstance("HmacSHA256")
        hkdf.init(S.toByteArray(), u.toByteArray())
        return hkdf.deriveKey("Caldera Derived Key".toByteArray(), 16)
    }

    fun passwordVerifierConfig(deviceGroupKey: String, deviceKey: String): PasswordVerifier {
        // RANDOM_PASSWORD = 40 random bytes, base64-encoded
        var randomPassword = ByteArray(40)
        SECURE_RANDOM.nextBytes(randomPassword)
        randomPassword = Base64.getEncoder().encode(randomPassword)

        // FULL_PASSWORD = SHA256_HASH(DeviceGroupKey + DeviceKey + ":" + RANDOM_PASSWORD)
        val fullPassword =
            hash(deviceGroupKey.toByteArray(), deviceKey.toByteArray(), ":".toByteArray(), randomPassword)

        val salt = ByteArray(16)
        SECURE_RANDOM.nextBytes(salt)

        val x = BigInteger(1, hash(salt, fullPassword))
        val verifier = G.modPow(x, N)

        return PasswordVerifier(
            randomPassword.toString(Charset.forName("UTF-8")),
            Base64.getEncoder().encodeToString(verifier.toByteArray()),
            Base64.getEncoder().encodeToString(BigInteger(1, salt).toByteArray())
        )
    }
}

data class PasswordVerifier(
    val devicePassword: String,
    val passwordVerifier: String,
    val salt: String
)
