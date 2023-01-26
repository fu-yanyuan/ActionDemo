package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/spruceid/siwe-go"
)

type verifyReq struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type errorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type nonceResp struct {
	Nonce string `json:"nonce"`
}

func nonce(c *gin.Context) {
	session := sessions.Default(c)

	session.Set("nonce", siwe.GenerateNonce())
	err := session.Save()
	if err != nil {
		panic(err)
	}

	nonce := nonceResp{session.Get("nonce").(string)}
	c.JSON(200, gin.H{
		"data": nonce,
	})
}

func verify(c *gin.Context) {
	var requestBody verifyReq
	var err error
	var message *siwe.Message
	optionalDomain := "api.soularis.dev"

	//session
	session := sessions.Default(c)

	if err = c.BindJSON(&requestBody); err != nil {
		errInfo := errorResp{Code: 123, Message: err.Error()}
		c.JSON(400, gin.H{
			"error": errInfo,
		})
		return
	}

	if message, err = siwe.ParseMessage(requestBody.Message); message == nil {
		errInfo := errorResp{Code: 123, Message: err.Error()}
		c.JSON(422, gin.H{
			"error": errInfo,
		})
		return
	}

	// VERIFY
	optionalNonce, _ := session.Get("nonce").(string)
	_, err = message.Verify(requestBody.Signature, &optionalDomain, &optionalNonce, nil)

	if err != nil {
		errInfo := errorResp{Code: 123, Message: err.Error()} // error code not determined
		c.JSON(422, gin.H{
			"error": errInfo,
		})
		return
	}

	c.Status(204)
}

func main() {
	r := gin.Default()

	//session
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/nonce", nonce)
	r.POST("/verify", verify)

	err := r.Run(":8080") //listen and serve on :8080
	if err != nil {
		panic(err)
	}
}
