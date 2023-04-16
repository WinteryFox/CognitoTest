import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder
import com.amazonaws.services.cognitoidp.model.*

fun main() {
    val poolId = System.getenv("POOL_ID")
    val clientId = System.getenv("CLIENT_ID")
    val clientSecret = System.getenv("CLIENT_SECRET")

    val helper = DeviceHelper()
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

    val email = System.getenv("EMAIL")
    val password = System.getenv("PASSWORD")

    val auth = provider.adminInitiateAuth(
        AdminInitiateAuthRequest()
            .withAuthFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
            .withAuthParameters(
                mapOf(
                    "USERNAME" to email,
                    "PASSWORD" to password,
                    "SECRET_HASH" to helper.secretHash(clientId, email, clientSecret)
                )
            )
            .withClientId(clientId)
            .withUserPoolId(poolId)
    )

    val deviceGroupKey = auth.authenticationResult.newDeviceMetadata.deviceGroupKey
    val deviceKey = auth.authenticationResult.newDeviceMetadata.deviceKey
    val config = helper.passwordVerifierConfig(deviceGroupKey, deviceKey)
    println("device key: $deviceKey")
    println("device group key: $deviceGroupKey")
    println("device password: ${config.devicePassword}")

    provider.confirmDevice(
        ConfirmDeviceRequest()
            .withDeviceName("Test")
            .withDeviceKey(deviceKey)
            .withDeviceSecretVerifierConfig(
                DeviceSecretVerifierConfigType()
                    .withPasswordVerifier(config.passwordVerifier)
                    .withSalt(config.salt)
            )
            .withAccessToken(auth.authenticationResult.accessToken)
    )
    println("confirmed device!")
}
