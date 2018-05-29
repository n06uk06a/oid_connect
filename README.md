# Google Open ID Connect for CloudFront Signed Cookie

## Getting Started

### Create OAuth2 client ID
* https://console.developers.google.com/

### Create CloudFront key pair
* Create CloudFront key pair.
    * Set key id as CFKeyID.
    * Download private key and encode with KMS. And set encoded key as CFKey.

### Build and deploy
```
$ GOOS=linux go build -o build/oidc
```

```
$ aws cloudformation package \
    --template-file template.yaml \
    --s3-bucket ${BUCKET_NAME} \
    --output-template-file package.yaml
```

```
$ aws cloudformation deploy \
    --template-file package.yaml \
    --stack-name OIDConnect \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides \
        KMSPrincipal=${KMS_KEY_ADMIN_ARN} \
        KMSAliasParameter=${KMS_ALIAS} \
        OAuthClientID=${OAUTH2_CLIENT_ID} \
        OAuthClientSecret=${OAuthClientSecret} \
        CFKeyID=${CLOUDFROMT_KEY_ID} \
        CFKey=${CFKey} \
        URLPattern=${URL_PATTERN} \
        JWSKey=${JWSKey} \
        HostedDomain=${GOOGLE_HOSTED_DOMAIN}
```

```
$ aws cloudformation deploy \
    --template-file package.yaml \
    --stack-name OIDConnect \
    --capabilities CAPABILITY_IAM \
    --parameter-overrides \
        KMSPrincipal=${KMS_KEY_ADMIN_ARN} \
        KMSAliasParameter=${KMS_ALIAS} \
        OAuthClientID=${OAUTH2_CLIENT_ID} \
        OAuthClientSecret=${OAuthClientSecret} \
        CFKeyID=${CLOUDFROMT_KEY_ID} \
        CFKey=${CFKey} \
        URLPattern=${URL_PATTERN} \
        JWSKey=${JWSKey} \
        HostedDomain=${GOOGLE_HOSTED_DOMAIN}
```

#### Note
CFKey, OAuthClientSecret, and JWSKey are encrypted by KMS.
So re-encrypt them as below.

```
$ CFKey=$(aws kms encrypt --key-id ${ALIAS_NAME} \
    --plaintext fileb://${FILENAME} \
    --query CiphertextBlob \
    --output text)
```

```
$ OAuthClientSecret=$(aws kms encrypt --key-id ${ALIAS_NAME} \
    --plaintext fileb://${FILENAME} \
    --query CiphertextBlob \
    --output text)
```

```
$ JWSKey=$(aws kms encrypt --key-id ${ALIAS_NAME} \
    --plaintext fileb://${FILENAME} \
    --query CiphertextBlob \
    --output text)
```

### Configure CloudFront
* Restrict the behavior of your domain.
* To configure forward */oauth/login* and */oauth/callback* to API Gateway.(Dont restrict access)

### Log in
* Call https://your-domain/login/login
* You'll be redirected to Authentication page.
* After authentication and authoirze, you'll be redirected to https://your-domain/

## Parameters
* KMSPrincipal: ARN of admin of KMS master key.
* KMSAliasParameter: Alias of KMS master key.
* OAuthClientID: OAuth2 Client ID.
* OAuthClientSecret: Encrypted OAuth2 Client Sercret.
* CFKeyID: Key ID of key pair for CloudFront.
* CFKey: Encrypted key of key pair for CloudFront.
* URLPattern: Allow URL Pattern for policy of signed cookie.
* JWSKey: Encrypted key string to encrypt state.(any strings will do.)
* HostedDomain: Set domain if you want to restrict domain of G Suite.
