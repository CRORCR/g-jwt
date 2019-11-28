package g_jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/jinzhu/gorm"
	"strings"
	"time"
)

type JwtClass struct {
}

var PubKey = `-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8NP+SYklqU1kTHrCRVQ\no2VI9jg3pxbCG6wXdmpoSwt30TeIWYUnBhDDZ22eLWADYPci5HwIRw6kphadDHB/\nK0cE79QWpo9hOo8/3hXCr0Tfs2MG5xlolqTn/svdf/tBtUypxe828mKU+YuNavX+\n8F60Yunq8ZRoaRlO3T+O0App4A6at5umG7qncZdL/GOzyyw8K+cYVkXN6DSOUs7T\ncigFMKywMuW1wh0SCDZjmebUGO+S4KKw1oEnzP6zO6RQqTfJVGsQnNJkczQ8vUQ/\n8l8Y2WohU/zmCsPgr/suSdyHWMv0KEoDjB0hCbhx3Aqy1GpYw/6gj1M949JN10Ti\n0wIDAQAB\n-----END PUBLIC KEY-----`

var Jwt = JwtClass{}

func (this *JwtClass) GetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(expireDuration).Unix()
	claims["iat"] = time.Now().Unix() // 颁发时间
	claims["payload"] = payload
	token.Claims = claims
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return ``, err
	}
	return tokenString, nil
}

func (this *JwtClass) VerifyJwt(tokenStr string, clientType string, address string, client *redis.Client, dataSql *gorm.DB) (bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(PubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		return false, err
	}
	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenStr, claims, nil)
	userID := claims[`payload`].(map[string]interface{})["user_id"]
	if userID.(int64) == 0 {
		return false, errors.New("clash login")
	}
	if checkLand(userID.(int64), clientType, address, client, dataSql) {
		return token.Valid, nil
	} else {
		return false, errors.New("clash login")
	}
}

func DecodePayloadOfJwtBody(tokenStr string) map[string]interface{} {
	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenStr, claims, nil)
	return claims[`payload`].(map[string]interface{})
}

func checkLand(userID int64, _type, ip string, client *redis.Client, dataSql *gorm.DB) bool {
	lastKey := fmt.Sprintf("land:%v:%v_%v", userID, ip, _type)
	_, err := client.Get(lastKey).Result()
	if err == nil {
		fmt.Println("存在记录，返回ok")
		return true
	}

	var history struct {
		UserId     uint64    `db:"user_id"`
		LoginIp    string    `db:"login_ip"`
		ClientType string    `db:"client_type"`
		CreatedAt  time.Time `db:"created_at"`
	}

	err = dataSql.Table("login_history").Where("user_id=? and client_type=?", userID, _type).Order("created_at desc").First(&history).Error

	if err != nil {
		return false
	}

	if history.UserId == 0 {
		return true
	}

	if strings.EqualFold(history.LoginIp, ip) {
		return true
	}
	lastKey = fmt.Sprintf("land:%v:%v_%v", history.UserId, history.LoginIp, history.ClientType)
	client.Set(lastKey, time.Now().Format("2006-01-02 03:04:05"), time.Second*300) //5分钟
	return false
}

func (this *JwtClass) VerifyJwtSkipClaimsValidation(tokenStr string) (bool, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(PubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}

func (this *JwtClass) MustVerifyJwtSkipClaimsValidation(tokenStr string) bool {
	valid, err := this.VerifyJwtSkipClaimsValidation(tokenStr)
	if err != nil {
		panic(err)
	}
	return valid
}

func (this *JwtClass) DecodeBodyOfJwt(tokenStr string) (map[string]interface{}, error) {
	claims := jwt.MapClaims{}
	parser := jwt.Parser{}
	_, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (this *JwtClass) MustDecodeBodyOfJwt(tokenStr string) map[string]interface{} {
	result, err := this.DecodeBodyOfJwt(tokenStr)
	if err != nil {
		panic(err)
	}
	return result
}

func (this *JwtClass) MustDecodePayloadOfJwtBody(tokenStr string) map[string]interface{} {
	return this.MustDecodeBodyOfJwt(tokenStr)[`payload`].(map[string]interface{})
}
