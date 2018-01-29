package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/joho/godotenv"
	"os"
	"log"
)

func main() {
	loadEnv()
	username := os.Getenv("COGNITO_USER_NAME")
	password := os.Getenv("COGNITO_PASSWORD")
	clientId := os.Getenv("COGNITO_CLIENT_ID")
	userPoolId := os.Getenv("COGNITO_USER_POOL_ID")
	// newPassword := os.Getenv("COGNITO_NEW_PASSWORD")

	svc := cognitoidentityprovider.New(session.New(), &aws.Config{Region: aws.String("us-west-2")})

	// ログイン
	params := &cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow: aws.String("ADMIN_NO_SRP_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(username),
			"PASSWORD": aws.String(password),
		},
		ClientId:   aws.String(clientId),
		UserPoolId: aws.String(userPoolId),
	}

	resp, err := svc.AdminInitiateAuth(params)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(resp)

	// 初期パスワード変更
	// session := resp.Session
	// r_params := &cognitoidentityprovider.AdminRespondToAuthChallengeInput{
	// 	ChallengeName: aws.String("NEW_PASSWORD_REQUIRED"),
	// 	ChallengeResponses: map[string]*string{
	// 		"NEW_PASSWORD": aws.String(newPassword),
	// 		"USERNAME":     aws.String(username),
	// 	},
	// 	ClientId:   aws.String(clientId),
	// 	Session:    session,
	// 	UserPoolId: aws.String(userPoolId),
	// }

	// r_resp, err := svc.AdminRespondToAuthChallenge(r_params)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	// fmt.Println(r_resp)

	// // ログアウト by AccessToken
	// o_params := &cognitoidentityprovider.GlobalSignOutInput{
	// 	AccessToken: aws.String(*resp.AuthenticationResult.AccessToken),
	// }
	// o_resp, err := svc.GlobalSignOut(o_params)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	return
	// }
	// fmt.Println(o_resp)
}

func loadEnv() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading %v\n", err)
	}
}
