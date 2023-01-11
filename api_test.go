package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/spruceid/siwe-go"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

const testDomain = "api.soularis.dev"

const testStatement = "Test statement for SIWE"
const testUri = "https://example.com"

var testIssuedAt = time.Now().UTC().Format(time.RFC3339)
var testExpirationTime = time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)

const testChainId = 1

var testOptions = map[string]interface{}{
	"statement":      testStatement,
	"chainId":        testChainId,
	"issuedAt":       testIssuedAt,
	"expirationTime": testExpirationTime,
	// "notBefore":      nil,
	// "requestId":      nil,
	// "resources":      nil,
}

type RespStruct struct {
	Data nonceResp `json:"data"`
}

func signHash(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func signMessage(message string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sign := signHash([]byte(message))
	signature, err := crypto.Sign(sign.Bytes(), privateKey)

	if err != nil {
		return nil, err
	}

	signature[64] += 27
	return signature, nil
}

func TestSIWE(t *testing.T) {
	//#1 KEYPAIR
	privateKey, _ := crypto.GenerateKey()
	publicKey := privateKey.PublicKey
	testAddress := crypto.PubkeyToAddress(publicKey)

	//#2 GET NONCE
	w := httptest.NewRecorder()
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/nonce", nonce)
	r.POST("/verify", verify)

	req := httptest.NewRequest("GET", "/nonce", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	nonceData := RespStruct{}
	respBody := w.Result().Body
	cookie := w.Result().Header.Get("Set-Cookie")
	defer respBody.Close()
	body, _ := io.ReadAll(respBody)

	err := json.Unmarshal(body, &nonceData) // for w.Result().Body
	assert.Nil(t, err)

	//#3 MESSAGE STRUCT
	testMessage, _ := siwe.InitMessage(
		testDomain,
		testAddress.String(),
		testUri,
		nonceData.Data.Nonce,
		testOptions,
	)
	testMessageStr := testMessage.String()

	//#4 Signature
	testSignature, _ := signMessage(testMessageStr, privateKey)
	testSignatureStr := hexutil.Encode(testSignature)

	reqBody := verifyReq{
		Message:   testMessageStr,
		Signature: testSignatureStr,
	}
	reqBodyJson, _ := json.Marshal(reqBody)

	w = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/verify", bytes.NewBuffer(reqBodyJson))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	r.ServeHTTP(w, req)

	assert.Equal(t, 204, w.Code)
}
