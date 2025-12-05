package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJWTFlow 测试完整的JWT流程
// 这个测试展示了JWT的完整使用流程：
// 1. 创建JWT管理器
// 2. 生成令牌对
// 3. 验证访问令牌
// 4. 提取用户信息
// 5. 使用刷新令牌获取新的令牌对
func TestJWTFlow(t *testing.T) {
	// 步骤1：创建JWT管理器
	// secretKey建议使用强随机字符串（至少32字符）
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute, // 访问令牌15分钟过期
		7*24*time.Hour, // 刷新令牌7天过期
		"test-issuer",
	)

	// 步骤2：准备用户Claims并生成令牌对
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:       12345,
			Email:        "test@example.com",
			Phone:        "+8613800138000",
			DeviceID:     "device-uuid-12345",
			Platform:     "mac",
			IP:           "192.168.1.100",
			Country:      "CN",
			Version:      "1.0.0",
			RegisterTime: time.Now().Unix(),
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err, "生成令牌对应该成功")
	require.NotNil(t, tokenPair, "令牌对不应为空")
	assert.NotEmpty(t, tokenPair.AccessToken, "访问令牌不应为空")
	assert.NotEmpty(t, tokenPair.RefreshToken, "刷新令牌不应为空")
	assert.Equal(t, int64(900), tokenPair.ExpiresIn, "访问令牌过期时间应为900秒（15分钟）")

	t.Logf("生成的访问令牌: %s", tokenPair.AccessToken)
	t.Logf("生成的刷新令牌: %s", tokenPair.RefreshToken)

	// 步骤3：验证访问令牌
	validatedClaims, err := manager.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err, "验证访问令牌应该成功")
	assert.Equal(t, claims.UserID, validatedClaims.UserID, "用户ID应该匹配")
	assert.Equal(t, claims.Email, validatedClaims.Email, "邮箱应该匹配")
	assert.Equal(t, claims.DeviceID, validatedClaims.DeviceID, "设备ID应该匹配")
	assert.Equal(t, claims.Platform, validatedClaims.Platform, "平台应该匹配")

	// 步骤4：提取完整用户信息
	userInfo, err := manager.ExtractUserInfo(tokenPair.AccessToken)
	require.NoError(t, err, "提取用户信息应该成功")
	assert.Equal(t, claims.UserID, userInfo.UserID, "用户ID应该匹配")
	assert.Equal(t, claims.Email, userInfo.Email, "邮箱应该匹配")
	assert.Equal(t, claims.Phone, userInfo.Phone, "手机号应该匹配")
	assert.Equal(t, claims.DeviceID, userInfo.DeviceID, "设备ID应该匹配")
	assert.Equal(t, claims.Platform, userInfo.Platform, "平台应该匹配")
	assert.Equal(t, claims.IP, userInfo.IP, "IP地址应该匹配")
	assert.Equal(t, claims.Country, userInfo.Country, "国家应该匹配")
	assert.Equal(t, claims.Version, userInfo.Version, "版本号应该匹配")

	t.Logf("提取的用户信息: UserID=%d, Email=%s, DeviceID=%s",
		userInfo.UserID, userInfo.Email, userInfo.DeviceID)

	// 步骤5：使用刷新令牌获取新的令牌对
	newTokenPair, err := manager.RefreshToken(
		tokenPair.RefreshToken,
		claims.DeviceID,
		claims.UserID,
		"192.168.1.101", // 新的IP
		"US",            // 新的国家
		"mac",
		"1.0.1", // 新的版本
	)
	require.NoError(t, err, "刷新令牌应该成功")
	assert.NotEmpty(t, newTokenPair.AccessToken, "新的访问令牌不应为空")
	assert.NotEmpty(t, newTokenPair.RefreshToken, "新的刷新令牌不应为空")
	assert.NotEqual(t, tokenPair.AccessToken, newTokenPair.AccessToken, "新的访问令牌应该与旧的不同")

	t.Logf("刷新后的新访问令牌: %s", newTokenPair.AccessToken)
}

// TestExtractUserID 测试提取用户ID
func TestExtractUserID(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   99999,
			DeviceID: "test-device",
			Platform: "ios",
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	userInfo, err := manager.ExtractUserInfo(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, userInfo.UserID, "提取的用户ID应该匹配")
}

// TestExtractDeviceID 测试提取设备ID
func TestExtractDeviceID(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   88888,
			DeviceID: "unique-device-id-xyz",
			Platform: "android",
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	userInfo, err := manager.ExtractUserInfo(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claims.DeviceID, userInfo.DeviceID, "提取的设备ID应该匹配")
}

// TestInvalidToken 测试无效的令牌
func TestInvalidToken(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// 测试空令牌
	_, err := manager.ValidateToken("")
	assert.Error(t, err, "空令牌应该返回错误")

	// 测试无效格式的令牌
	_, err = manager.ValidateToken("invalid.token.format")
	assert.Error(t, err, "无效格式的令牌应该返回错误")

	// 测试篡改过的令牌
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   11111,
			DeviceID: "test-device",
			Platform: "web",
		},
	}
	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	// 篡改令牌（在末尾添加字符）
	tamperedToken := tokenPair.AccessToken + "tampered"
	_, err = manager.ValidateToken(tamperedToken)
	assert.Error(t, err, "篡改过的令牌应该返回错误")
}

// TestExpiredToken 测试过期的令牌
func TestExpiredToken(t *testing.T) {
	// 创建一个访问令牌过期时间非常短的管理器
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		1*time.Millisecond, // 1毫秒后过期
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   22222,
			DeviceID: "test-device",
			Platform: "mac",
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	// 等待令牌过期
	time.Sleep(10 * time.Millisecond)

	// 尝试验证过期的令牌
	_, err = manager.ValidateToken(tokenPair.AccessToken)
	assert.Error(t, err, "过期的令牌应该返回错误")
}

// TestRefreshTokenMismatch 测试刷新令牌时用户ID或设备ID不匹配的情况
func TestRefreshTokenMismatch(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   33333,
			DeviceID: "original-device",
			Platform: "win",
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	// 测试用户ID不匹配
	_, err = manager.RefreshToken(
		tokenPair.RefreshToken,
		"original-device",
		99999, // 错误的用户ID
		"192.168.1.1",
		"CN",
		"win",
		"1.0.0",
	)
	assert.Error(t, err, "用户ID不匹配应该返回错误")
	assert.Contains(t, err.Error(), "用户ID不匹配", "错误信息应该包含'用户ID不匹配'")

	// 测试设备ID不匹配
	_, err = manager.RefreshToken(
		tokenPair.RefreshToken,
		"wrong-device", // 错误的设备ID
		33333,
		"192.168.1.1",
		"CN",
		"win",
		"1.0.0",
	)
	assert.Error(t, err, "设备ID不匹配应该返回错误")
	assert.Contains(t, err.Error(), "设备ID不匹配", "错误信息应该包含'设备ID不匹配'")
}

// TestAccessTokenAsRefreshToken 测试将访问令牌当作刷新令牌使用
func TestAccessTokenAsRefreshToken(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   44444,
			DeviceID: "test-device",
			Platform: "ios",
		},
	}

	tokenPair, err := manager.GenerateToken(claims)
	require.NoError(t, err)

	// 尝试将访问令牌当作刷新令牌使用
	_, err = manager.RefreshToken(
		tokenPair.AccessToken, // 错误：使用访问令牌而不是刷新令牌
		"test-device",
		44444,
		"192.168.1.1",
		"CN",
		"ios",
		"1.0.0",
	)
	assert.Error(t, err, "访问令牌不应该被当作刷新令牌使用")
	assert.Contains(t, err.Error(), "不是刷新令牌", "错误信息应该包含'不是刷新令牌'")
}

// TestDifferentSecretKey 测试使用不同密钥验证令牌
func TestDifferentSecretKey(t *testing.T) {
	// 使用第一个密钥生成令牌
	manager1 := NewJWTManager(
		"first-secret-key-for-jwt-signing-123456",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   55555,
			DeviceID: "test-device",
			Platform: "web",
		},
	}

	tokenPair, err := manager1.GenerateToken(claims)
	require.NoError(t, err)

	// 使用不同的密钥尝试验证令牌
	manager2 := NewJWTManager(
		"second-different-secret-key-for-jwt-654321",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	_, err = manager2.ValidateToken(tokenPair.AccessToken)
	assert.Error(t, err, "使用不同密钥验证令牌应该失败")
}
