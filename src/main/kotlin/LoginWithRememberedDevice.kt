import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest
import com.amazonaws.services.cognitoidp.model.AdminRespondToAuthChallengeRequest
import com.amazonaws.services.cognitoidp.model.AuthFlowType
import java.text.SimpleDateFormat
import java.util.*

fun main() {
    val poolId = System.getenv("POOL_ID")
    val clientId = System.getenv("CLIENT_ID")
    val clientSecret = System.getenv("CLIENT_SECRET")

    val email = System.getenv("EMAIL")
    val password = System.getenv("PASSWORD")

    val deviceKey = System.getenv("DEVICE_KEY")
    val deviceGroupKey = System.getenv("DEVICE_GROUP_KEY")
    val devicePassword = System.getenv("DEVICE_PASSWORD")

    val helper = DeviceHelper(
        deviceKey,
        deviceGroupKey
    )

    val provider: AWSCognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
        .standard()
        .withCredentials(
            AWSStaticCredentialsProvider(
                BasicAWSCredentials(
                    System.getenv("ACCESS_KEY"),
                    System.getenv("SECRET_KEY")
                )
            )
        )
        .withRegion(Regions.EU_CENTRAL_1)
        .build()

    val auth = provider.adminInitiateAuth(
        AdminInitiateAuthRequest()
            .withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
            .withAuthParameters(
                mapOf(
                    "USERNAME" to email,
                    "PASSWORD" to password,
                    "SECRET_HASH" to secretHash(clientId, email, clientSecret),
                    "DEVICE_KEY" to deviceKey
                )
            )
            .withClientId(clientId)
            .withUserPoolId(poolId)
    )
    println(auth.challengeName)
    println(auth.challengeParameters)

    val date = SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
    date.timeZone = SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC")
    val timestamp = date.format(Date())

    val deviceSrpAuth = provider.adminRespondToAuthChallenge(
        AdminRespondToAuthChallengeRequest()
            .withChallengeName("DEVICE_SRP_AUTH")
            .withChallengeResponses(
                mapOf(
                    "DEVICE_KEY" to deviceKey,
                    "USERNAME" to email,
                    "SRP_A" to helper.srpa(),
                    "SECRET_HASH" to secretHash(
                        clientId,
                        email,
                        clientSecret
                    )
                )
            )
            .withUserPoolId(poolId)
            .withClientId(clientId)
            .withSession(auth.session)
    )
    println(deviceSrpAuth.challengeName)
    println(deviceSrpAuth.challengeParameters)

    val devicePasswordVerifier = provider.adminRespondToAuthChallenge(
        AdminRespondToAuthChallengeRequest()
            .withChallengeName("DEVICE_PASSWORD_VERIFIER")
            .withChallengeResponses(
                mapOf(
                    "USERNAME" to deviceSrpAuth.challengeParameters["USERNAME"]!!,
                    "PASSWORD_CLAIM_SECRET_BLOCK" to deviceSrpAuth.challengeParameters["SECRET_BLOCK"]!!,
                    "TIMESTAMP" to timestamp,
                    "PASSWORD_CLAIM_SIGNATURE" to helper.passwordClaimSignature(
                        devicePassword,
                        deviceSrpAuth.challengeParameters["SRP_B"]!!,
                        deviceSrpAuth.challengeParameters["SALT"]!!,
                        timestamp,
                        deviceSrpAuth.challengeParameters["SECRET_BLOCK"]!!
                    ),
                    "DEVICE_KEY" to deviceKey,
                    "SECRET_HASH" to secretHash(
                        clientId,
                        deviceSrpAuth.challengeParameters["USERNAME"]!!,
                        clientSecret
                    )
                )
            )
            .withUserPoolId(poolId)
            .withClientId(clientId)
            .withSession(deviceSrpAuth.session)
    )
    println(devicePasswordVerifier.authenticationResult)
}
