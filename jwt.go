package jwt

import (
	"context"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type JWTService interface {
	// GenerateToken 生成JWT令牌对（访问令牌 + 刷新令牌）
	GenerateToken(ctx context.Context, claims *JWTClaims) (*JWTToken, error)

	// ValidateToken 验证访问令牌的有效性，设备号防泄漏
	ValidateToken(ctx context.Context, deviceId string, tokenString string) (*JWTClaims, error)

	// RefreshToken 使用刷新令牌获取新的令牌对
	RefreshToken(ctx context.Context, deviceId string, refreshTokenString string, newClaims *JWTClaims) (*JWTToken, error)

	// ExtractUserInfo 从访问令牌中提取用户信息 「普通用户，不支持游客模式」
	ExtractUserInfo(ctx context.Context, deviceId string, tokenString string) (UserInfo, error)

	// ExtractUserInfoWithGuest 支持游客模式：如果token为空返回游客信息，如果token存在则必须验证通过
	ExtractUserInfoWithGuest(ctx context.Context, deviceId string, tokenString string) (UserInfo, error)
}

var (
	_ JWTService = (*JWTManager)(nil)
	_ JWTService = (*JWTManagerV2)(nil)
)

type UserInfo struct {
	UserID       int64  `json:"userId"`                 // 用户ID
	Email        string `json:"email,omitempty"`        // 邮箱
	Phone        string `json:"phone,omitempty"`        // 手机号
	DeviceID     string `json:"deviceId"`               // 设备号
	Platform     string `json:"platform"`               // 平台（mac、win、ios、android等）
	IP           string `json:"ip,omitempty"`           // IP地址
	Country      string `json:"country,omitempty"`      // 国家代码
	Version      string `json:"version,omitempty"`      // 客户端版本号
	RegisterTime int64  `json:"registerTime,omitempty"` // 注册时间（Unix时间戳）
	IsGuest      bool   `json:"isGuest"`                // 是否为游客模式
}

// JWTClaims 访问令牌(Access Token)的payload部分
type JWTClaims struct {
	UserInfo
	TokenVersion         int64 `json:"tokenVersion,omitempty"` // Token版本号（纳秒时间戳），用于互踢功能
	jwt.RegisteredClaims       // JWT标准声明字段（iss、exp、iat等）
}

// JWTManager JWT管理器 负责JWT令牌的生成、验证和刷新
type JWTManager struct {
	secretKey     string        // 密钥，用于签名和验证JWT令牌
	accessExpiry  time.Duration // 令牌过期时间
	refreshExpiry time.Duration // 刷新令牌过期时间
	issuer        string        // 令牌签发者
}

// JWTToken accessToken用于API调用，refreshToken获取新的token
type JWTToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"` // accessToken过期时间，单位：秒
}

// NewJWTManager 创建JWT管理器 secretKey: 用于签名的密钥，使用强随机字符串 issuer: 签发者，应用名称或域名
func NewJWTManager(secretKey string, accessExpiry, refreshExpiry time.Duration, issuer string) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		issuer:        issuer,
	}
}

// GenerateToken 生成JWT令牌对（访问令牌 + 刷新令牌）
func (j *JWTManager) GenerateToken(_ context.Context, claims *JWTClaims) (*JWTToken, error) {
	now := time.Now()

	// 1、生成访问令牌
	accessClaims := *claims
	accessClaims.Issuer = j.issuer                                       // 设置签发者
	accessClaims.IssuedAt = jwt.NewNumericDate(now)                      // 设置签发时间
	accessClaims.ExpiresAt = jwt.NewNumericDate(now.Add(j.accessExpiry)) // 设置过期时间

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &accessClaims).SignedString([]byte(j.secretKey))
	if err != nil {
		return nil, fmt.Errorf("生成访问令牌失败,uid:%d,err:%w", claims.UserID, err)
	}

	// 2、生成刷新令牌
	refreshClaims := jwt.MapClaims{
		"userId":   claims.UserID,                   // 用户ID
		"deviceId": claims.DeviceID,                 // 设备ID
		"iss":      j.issuer,                        // 签发者
		"iat":      now.Unix(),                      // 签发时间
		"exp":      now.Add(j.refreshExpiry).Unix(), // 过期时间
		"type":     "refresh",                       // 令牌类型标识，防止令牌混用
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(j.secretKey))
	if err != nil {
		return nil, fmt.Errorf("生成刷新令牌失败: %w", err)
	}

	return &JWTToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(j.accessExpiry.Seconds()),
	}, nil
}

// ValidateToken 验证访问令牌的有效性
func (j *JWTManager) ValidateToken(_ context.Context, deviceId string, tokenString string) (*JWTClaims, error) {
	// 1、解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法是否为HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名方法: %v", token.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("解析令牌失败: %w", err)
	}

	// 2、验证令牌有效性
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("无效的令牌")
	}

	// 3、验证设备ID是否匹配（防止令牌盗用）
	if claims.DeviceID != deviceId {
		return nil, errors.New("设备ID不匹配")
	}

	return claims, nil
}

// ValidateRefreshToken 验证刷新令牌的有效性
func (j *JWTManager) ValidateRefreshToken(_ context.Context, deviceId string, tokenString string) (map[string]interface{}, error) {
	// 1、解析刷新令牌
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法是否为HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名方法: %v", token.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("解析刷新令牌失败: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("无效的刷新令牌")
	}

	// 2. 设备ID是否匹配（防止令牌盗用）
	refreshDeviceID, ok := claims["deviceId"].(string)
	if !ok || refreshDeviceID != deviceId {
		return nil, errors.New("设备ID不匹配")
	}

	// 3、检查token类型，防止访问令牌被误用为刷新令牌
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, errors.New("不是刷新令牌")
	}

	return claims, nil
}

// RefreshToken 使用刷新令牌获取新的令牌对
func (j *JWTManager) RefreshToken(ctx context.Context, deviceId string, refreshTokenString string, newClaims *JWTClaims) (*JWTToken, error) {
	// 1、验证刷新令牌
	refreshClaims, err := j.ValidateRefreshToken(ctx, deviceId, refreshTokenString)
	if err != nil {
		return nil, err
	}

	// 2、验证用户ID和设备ID匹配，防止令牌被盗用
	refreshUserID, ok := refreshClaims["userId"].(float64)
	if !ok || int64(refreshUserID) != newClaims.UserID {
		return nil, errors.New("用户ID不匹配")
	}

	refreshDeviceID, ok := refreshClaims["deviceId"].(string)
	if !ok || refreshDeviceID != newClaims.DeviceID {
		return nil, errors.New("设备ID不匹配")
	}

	// 3、使用新的Claims生成令牌对
	return j.GenerateToken(ctx, newClaims)
}

// ExtractUserInfo 从访问令牌中提取用户信息
func (j *JWTManager) ExtractUserInfo(ctx context.Context, deviceId string, tokenString string) (UserInfo, error) {
	// 验证并解析令牌
	claims, err := j.ValidateToken(ctx, deviceId, tokenString)
	if err != nil {
		return UserInfo{}, err
	}
	return claims.UserInfo, nil
}

// ExtractUserInfoWithGuest 支持游客模式：如果token为空返回游客信息，如果token存在则必须验证通过
// - 如果 deviceId 为空：返回错误（无效数据）
// - 如果 tokenString 为空：返回游客信息，不报错
// - 如果 tokenString 不为空但无效/过期：返回错误，要求重新登录
// - 如果 tokenString 有效：返回用户信息
func (j *JWTManager) ExtractUserInfoWithGuest(ctx context.Context, deviceId string, tokenString string) (UserInfo, error) {
	// 验证 deviceId 不能为空
	if deviceId == "" {
		return UserInfo{}, errors.New("设备ID不能为空")
	}

	// 如果token为空，直接返回游客信息
	if tokenString == "" {
		return j.createGuestUserInfo(deviceId), nil
	}

	// token不为空，必须验证通过
	userInfo, err := j.ExtractUserInfo(ctx, deviceId, tokenString)
	if err != nil {
		// token无效、过期或验证失败，返回错误要求重新登录
		return UserInfo{}, err
	}

	// token有效，返回正常用户信息
	userInfo.IsGuest = false
	return userInfo, nil
}

// createGuestUserInfo 创建游客用户信息
func (j *JWTManager) createGuestUserInfo(deviceId string) UserInfo {
	return UserInfo{
		UserID:   0, // 游客用户ID为0
		DeviceID: deviceId,
		IsGuest:  true,
	}
}
