package jwt

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

// UserInfo 用户信息结构体
// 包含用户身份、设备信息和其他关键字段
// 用于JWT Claims的数据载体，也用于从令牌中提取用户信息
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
}

// JWTClaims JWT载荷结构体
// 用于访问令牌(Access Token)的payload部分
// 组合了UserInfo和JWT标准声明
type JWTClaims struct {
	UserInfo             // 嵌入用户信息，字段会被提升到外层
	jwt.RegisteredClaims // JWT标准声明字段（iss、exp、iat等）
}

// JWTManager JWT管理器 负责JWT令牌的生成、验证和刷新
type JWTManager struct {
	secretKey     string        // 密钥，用于签名和验证JWT令牌
	accessExpiry  time.Duration // 令牌过期时间
	refreshExpiry time.Duration // 刷新令牌过期时间
	issuer        string        // 令牌签发者
}

// JWTToken JWT令牌对
// 包含访问令牌和刷新令牌
// 访问令牌用于API调用，刷新令牌用于获取新的访问令牌
type JWTToken struct {
	AccessToken  string `json:"accessToken"`  // 访问令牌，用于API请求认证
	RefreshToken string `json:"refreshToken"` // 刷新令牌，用于获取新的访问令牌
	ExpiresIn    int64  `json:"expiresIn"`    // 访问令牌过期时间，单位：秒
}

// NewJWTManager 创建JWT管理器
// 参数：
//   - secretKey: 用于签名的密钥，建议使用强随机字符串（至少32字符）
//   - accessExpiry: 访问令牌有效期，建议15分钟到1小时
//   - refreshExpiry: 刷新令牌有效期，建议7天到30天
//   - issuer: 令牌签发者标识，通常是应用名称或域名
//
// 返回：JWT管理器实例
func NewJWTManager(secretKey string, accessExpiry, refreshExpiry time.Duration, issuer string) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		issuer:        issuer,
	}
}

// GenerateToken 生成JWT令牌对（访问令牌 + 刷新令牌）
// 参数：
//   - claims: JWT载荷，包含用户身份和设备信息
//
// 返回：
//   - *JWTToken: 包含访问令牌和刷新令牌的令牌对
//   - error: 生成失败时返回错误
//
// 流程：
//  1. 生成访问令牌（包含完整用户信息，有效期短）
//  2. 生成刷新令牌（仅包含最小必要信息，有效期长）
//  3. 返回令牌对
func (j *JWTManager) GenerateToken(claims *JWTClaims) (*JWTToken, error) {
	now := time.Now()

	// 步骤1：生成访问令牌
	// 访问令牌包含完整的用户信息，用于API认证
	accessClaims := *claims
	accessClaims.Issuer = j.issuer                                       // 设置签发者
	accessClaims.IssuedAt = jwt.NewNumericDate(now)                      // 设置签发时间
	accessClaims.ExpiresAt = jwt.NewNumericDate(now.Add(j.accessExpiry)) // 设置过期时间

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &accessClaims).SignedString([]byte(j.secretKey))
	if err != nil {
		return nil, fmt.Errorf("生成访问令牌失败: %w", err)
	}

	// 步骤2：生成刷新令牌
	// 刷新令牌只包含最少必要信息（用户ID和设备ID），降低安全风险
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

	// 步骤3：返回令牌对
	return &JWTToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(j.accessExpiry.Seconds()),
	}, nil
}

// ValidateToken 验证访问令牌的有效性
// 参数：
//   - tokenString: JWT访问令牌字符串
//
// 返回：
//   - *JWTClaims: 解析后的JWT载荷信息
//   - error: 验证失败时返回错误（如令牌过期、签名无效等）
//
// 流程：
//  1. 解析令牌并验证签名方法
//  2. 验证令牌签名和有效期
//  3. 返回解析后的Claims
func (j *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
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

	// 3、返回Claims
	return claims, nil
}

// ValidateRefreshToken 验证刷新令牌的有效性
func (j *JWTManager) ValidateRefreshToken(tokenString string) (map[string]interface{}, error) {
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

	// 2、检查token类型，防止访问令牌被误用为刷新令牌
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, errors.New("不是刷新令牌")
	}

	// 3、返回Claims
	return claims, nil
}

// RefreshToken 使用刷新令牌获取新的令牌对
// 返回：新的令牌对（访问令牌 + 刷新令牌）
// 流程：
//  1. 验证刷新令牌的有效性
//  2. 验证用户ID和设备ID是否匹配（防止令牌盗用）
//  3. 生成新的令牌对并返回
func (j *JWTManager) RefreshToken(refreshTokenString string, deviceID string, userID int64, ip, country, platform, version string) (*JWTToken, error) {
	// 步骤1：验证刷新令牌
	claims, err := j.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, err
	}

	// 步骤2：验证用户ID和设备ID匹配，防止令牌被盗用
	// JSON解析时数字类型会被转换为float64
	refreshUserID, ok := claims["userId"].(float64)
	if !ok || int64(refreshUserID) != userID {
		return nil, errors.New("用户ID不匹配")
	}

	refreshDeviceID, ok := claims["deviceId"].(string)
	if !ok || refreshDeviceID != deviceID {
		return nil, errors.New("设备ID不匹配")
	}

	// 步骤3：生成新的令牌对
	newClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   userID,
			DeviceID: deviceID,
			Platform: platform,
			IP:       ip,
			Country:  country,
			Version:  version,
		},
	}

	return j.GenerateToken(newClaims)
}

// ExtractUserInfo 从访问令牌中提取完整的用户信息
// - error: 提取失败时返回错误（如令牌过期、签名无效等）
// 使用场景：需要获取完整用户信息时使用此方法，避免多次解析令牌
func (j *JWTManager) ExtractUserInfo(tokenString string) (*UserInfo, error) {
	// 验证并解析令牌
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	return &claims.UserInfo, nil
}
