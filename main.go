package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront/sign"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	plus "google.golang.org/api/plus/v1"
)

var sess = session.New()
var clientID = os.Getenv("OAUTH_CLIENT_ID")
var clientSecretEncrypted = os.Getenv("OAUTH_CLIENT_SECRET")
var clientSecret string
var cfKeyID = os.Getenv("CF_KEY_ID")
var cfKeyEncrypted = os.Getenv("CF_KEY")
var privKey *rsa.PrivateKey
var signer *sign.CookieSigner
var urlPattern = os.Getenv("URL_PATTERN")
var provider oidc.Provider
var jwsKey = []byte(os.Getenv("JWS_KEY"))
var hostedDomain = os.Getenv("HOSTED_DOMAIN")

func init() {
	var err error
	clientSecret, err = decrypt(clientSecretEncrypted)
	if err != nil {
		log.Fatal(err)
	}
	cfKey, err := decrypt(cfKeyEncrypted)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := readPrivateKey([]byte(cfKey))
	if err != nil {
		log.Fatal(err.Error())
	}
	signer = sign.NewCookieSigner(cfKeyID, privKey)
}

func decrypt(encrypted string) (string, error) {
	kmsClient := kms.New(sess)
	data, _ := base64.StdEncoding.DecodeString(encrypted)
	input := &kms.DecryptInput{
		CiphertextBlob: []byte(data),
	}
	result, err := kmsClient.Decrypt(input)
	if err != nil {
		return "", err
	}
	decrypted, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(result.Plaintext))
	return string(decrypted), nil
}

func readPrivateKey(signature []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(signature))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key type : %s", block.Type)
	}

	var key *rsa.PrivateKey
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, err
	}

	return key, nil
}

func generateToken(subject string, now int64) (string, error) {
	duration := 5 * time.Minute
	claims := &jwt.StandardClaims{
		Subject:   subject,
		IssuedAt:  now,
		ExpiresAt: time.Unix(now, 0).Add(duration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwsKey)
}

func verifyToken(tokenString string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := errors.New("Unexpected signing method")
			return nil, err
		}
		return jwsKey, nil
	})
	if err != nil {
		err = errors.Wrap(err, "Token is invalid")
		return nil, err
	}
	if !parsedToken.Valid {
		return nil, errors.New("Token is invalid")
	}
	return parsedToken, nil
}

func signedCookie() map[string]string {
	expiry := time.Now().Add(1 * time.Hour)
	cookies, err := signer.Sign(urlPattern, expiry)
	if err != nil {
		log.Fatalf("Failed to sign url, err: %s\n", err.Error())
	}
	for _, cookie := range cookies {
		cookie.Expires = expiry
		cookie.HttpOnly = true
		cookie.Secure = true
		cookie.Path = "/"
	}
	return map[string]string{
		"set-cookie": cookies[0].String(),
		"Set-cookie": cookies[1].String(),
		"Set-Cookie": cookies[2].String(),
	}
}

func login(req events.APIGatewayProxyRequest, oauth2Config oauth2.Config) (events.APIGatewayProxyResponse, error) {

	state, err := generateToken(uuid.NewV4().String(), time.Now().Unix())
	if err != nil {
		log.Fatal(err)
	}
	var opt oauth2.AuthCodeOption
	if hostedDomain != "" {
		opt = oauth2.SetAuthURLParam("hd", hostedDomain)
	}
	url := oauth2Config.AuthCodeURL(state, opt)
	return events.APIGatewayProxyResponse{
		StatusCode: 302,
		Headers: map[string]string{
			"Location": url,
		},
	}, nil
}

func callback(req events.APIGatewayProxyRequest, oauth2Config oauth2.Config) (events.APIGatewayProxyResponse, error) {

	state := req.QueryStringParameters["state"]
	if _, err := verifyToken(state); err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	oauth2Token, err := oauth2Config.Exchange(ctx, req.QueryStringParameters["code"])
	if err != nil {
		log.Fatal(err)
	}
	if oauth2Token.Valid() == false {
		log.Fatal(errors.New("invaild token"))
	}

	client := oauth2.NewClient(ctx, oauth2Config.TokenSource(ctx, oauth2Token))
	plusService, err := plus.New(client)
	if err != nil {
		return events.APIGatewayProxyResponse{}, err
	}
	person, err := plusService.People.Get("me").Do()
	if err != nil {
		log.Fatal(err)
	}
	personJSON, _ := json.Marshal(person)
	log.Print(string(personJSON))

	headers := signedCookie()
	u, _ := url.Parse(oauth2Config.RedirectURL)
	u.Path = ""
	headers["Location"] = u.String()

	return events.APIGatewayProxyResponse{
		StatusCode: 302,
		Headers:    headers,
	}, nil
}

func getOAuth2Config(req events.APIGatewayProxyRequest) oauth2.Config {
	headers := req.Headers
	var host string
	if headers["X-Forwarded-Host"] != "" {
		host = headers["X-Forwarded-Host"]
	} else {
		host = headers["Host"]
	}
	proto := headers["X-Forwarded-Proto"]
	port := headers["X-Forwarded-Port"]
	if port != "" && (proto == "http" && port != "80" || proto == "https" && port != "443") {
		host = host + ":" + port
	}
	u := url.URL{
		Scheme: proto,
		Host:   host,
		Path:   "oauth/callback",
	}
	return oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  u.String(),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid", "email", "profile"},
	}
}

// handler handle request
func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	eventJSON, _ := json.Marshal(req)
	log.Print(string(eventJSON))

	oauth2Config := getOAuth2Config(req)

	switch req.Path {
	case "/oauth/login":
		return login(req, oauth2Config)
	case "/oauth/callback":
		return callback(req, oauth2Config)
	default:
		return events.APIGatewayProxyResponse{
			StatusCode: 404,
		}, nil
	}
}

func main() {
	lambda.Start(handler)
}
