package jwt

import (
	"context"
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err, "生成令牌对应该成功")
	require.NotNil(t, tokenPair, "令牌对不应为空")
	assert.NotEmpty(t, tokenPair.AccessToken, "访问令牌不应为空")
	assert.NotEmpty(t, tokenPair.RefreshToken, "刷新令牌不应为空")
	assert.Equal(t, int64(900), tokenPair.ExpiresIn, "访问令牌过期时间应为900秒（15分钟）")

	t.Logf("生成的访问令牌: %s", tokenPair.AccessToken)
	t.Logf("生成的刷新令牌: %s", tokenPair.RefreshToken)

	// 步骤3：验证访问令牌
	validatedClaims, err := manager.ValidateToken(ctx, claims.DeviceID, tokenPair.AccessToken)
	require.NoError(t, err, "验证访问令牌应该成功")
	assert.Equal(t, claims.UserID, validatedClaims.UserID, "用户ID应该匹配")
	assert.Equal(t, claims.Email, validatedClaims.Email, "邮箱应该匹配")
	assert.Equal(t, claims.DeviceID, validatedClaims.DeviceID, "设备ID应该匹配")
	assert.Equal(t, claims.Platform, validatedClaims.Platform, "平台应该匹配")

	// 步骤4：提取完整用户信息
	userInfo, err := manager.ExtractUserInfo(ctx, claims.DeviceID, tokenPair.AccessToken)
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
	// 准备新的Claims，可以更新IP、国家、版本等信息
	newClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:       claims.UserID,       // 用户ID和设备ID必须与刷新令牌匹配
			DeviceID:     claims.DeviceID,     // 用户ID和设备ID必须与刷新令牌匹配
			Email:        claims.Email,        // 保持原有信息
			Phone:        claims.Phone,        // 保持原有信息
			Platform:     claims.Platform,     // 保持平台信息
			IP:           "192.168.1.101",     // 更新为新的IP
			Country:      "US",                // 更新为新的国家
			Version:      "1.0.1",             // 更新为新的版本
			RegisterTime: claims.RegisterTime, // 保持注册时间
		},
	}
	newTokenPair, err := manager.RefreshToken(ctx, newClaims.DeviceID, tokenPair.RefreshToken, newClaims)
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	userInfo, err := manager.ExtractUserInfo(ctx, claims.DeviceID, tokenPair.AccessToken)
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	userInfo, err := manager.ExtractUserInfo(ctx, claims.DeviceID, tokenPair.AccessToken)
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

	ctx := context.Background()

	// 测试空令牌
	_, err := manager.ValidateToken(ctx, "test-device", "")
	assert.Error(t, err, "空令牌应该返回错误")

	// 测试无效格式的令牌
	_, err = manager.ValidateToken(ctx, "test-device", "invalid.token.format")
	assert.Error(t, err, "无效格式的令牌应该返回错误")

	// 测试篡改过的令牌
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   11111,
			DeviceID: "test-device",
			Platform: "web",
		},
	}
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 篡改令牌（在末尾添加字符）
	tamperedToken := tokenPair.AccessToken + "tampered"
	_, err = manager.ValidateToken(ctx, claims.DeviceID, tamperedToken)
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 等待令牌过期
	time.Sleep(10 * time.Millisecond)

	// 尝试验证过期的令牌
	_, err = manager.ValidateToken(ctx, claims.DeviceID, tokenPair.AccessToken)
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 测试用户ID不匹配
	wrongUserIDClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   99999, // 错误的用户ID
			DeviceID: "original-device",
			Platform: "win",
		},
	}
	_, err = manager.RefreshToken(ctx, wrongUserIDClaims.DeviceID, tokenPair.RefreshToken, wrongUserIDClaims)
	assert.Error(t, err, "用户ID不匹配应该返回错误")
	assert.Contains(t, err.Error(), "用户ID不匹配", "错误信息应该包含'用户ID不匹配'")

	// 测试设备ID不匹配
	wrongDeviceClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   33333,
			DeviceID: "wrong-device", // 错误的设备ID
			Platform: "win",
		},
	}
	_, err = manager.RefreshToken(ctx, wrongDeviceClaims.DeviceID, tokenPair.RefreshToken, wrongDeviceClaims)
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

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 尝试将访问令牌当作刷新令牌使用
	refreshClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   44444,
			DeviceID: "test-device",
			Platform: "ios",
		},
	}
	_, err = manager.RefreshToken(
		ctx,
		refreshClaims.DeviceID,
		tokenPair.AccessToken, // 错误：使用访问令牌而不是刷新令牌
		refreshClaims,
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

	ctx := context.Background()
	tokenPair, err := manager1.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 使用不同的密钥尝试验证令牌
	manager2 := NewJWTManager(
		"second-different-secret-key-for-jwt-654321",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	_, err = manager2.ValidateToken(ctx, claims.DeviceID, tokenPair.AccessToken)
	assert.Error(t, err, "使用不同密钥验证令牌应该失败")
}

// TestDeviceIDMismatch 测试设备ID不匹配时访问令牌验证失败
func TestDeviceIDMismatch(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// 用户在设备A上登录，生成令牌
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   66666,
			DeviceID: "device-A",
			Platform: "mac",
			Email:    "user@example.com",
		},
	}

	ctx := context.Background()
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 测试在正确的设备上验证令牌（应该成功）
	validatedClaims, err := manager.ValidateToken(ctx, "device-A", tokenPair.AccessToken)
	require.NoError(t, err, "在正确的设备上验证应该成功")
	assert.Equal(t, claims.UserID, validatedClaims.UserID, "用户ID应该匹配")

	// 测试在错误的设备上验证令牌（应该失败，防止令牌盗用）
	_, err = manager.ValidateToken(ctx, "device-B", tokenPair.AccessToken)
	assert.Error(t, err, "在不同设备上验证应该失败")
	assert.Contains(t, err.Error(), "设备ID不匹配", "错误信息应该包含'设备ID不匹配'")

	// 测试提取用户信息时设备ID不匹配
	_, err = manager.ExtractUserInfo(ctx, "device-C", tokenPair.AccessToken)
	assert.Error(t, err, "使用错误的设备ID提取用户信息应该失败")
	assert.Contains(t, err.Error(), "设备ID不匹配", "错误信息应该包含'设备ID不匹配'")
}

// TestGuestMode 测试游客模式
func TestGuestMode(t *testing.T) {
	manager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		15*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	ctx := context.Background()

	// 测试1：空token应该返回游客信息，不报错
	guestInfo, err := manager.ExtractUserInfoWithGuest(ctx, "guest-device-1", "")
	require.NoError(t, err, "空token不应该返回错误")
	assert.True(t, guestInfo.IsGuest, "空token应该返回游客模式")
	assert.Equal(t, int64(0), guestInfo.UserID, "游客的UserID应该为0")
	assert.Equal(t, "guest-device-1", guestInfo.DeviceID, "设备ID应该匹配")

	// 测试2：无效token应该返回错误（要求重新登录）
	_, err = manager.ExtractUserInfoWithGuest(ctx, "guest-device-2", "invalid.token.string")
	assert.Error(t, err, "无效token应该返回错误")

	// 测试3：有效token应该返回正常用户信息
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   12345,
			Email:    "test@example.com",
			DeviceID: "normal-device",
			Platform: "mac",
		},
	}
	tokenPair, err := manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	normalUserInfo, err := manager.ExtractUserInfoWithGuest(ctx, "normal-device", tokenPair.AccessToken)
	require.NoError(t, err, "有效token应该验证成功")
	assert.False(t, normalUserInfo.IsGuest, "有效token不应该是游客模式")
	assert.Equal(t, int64(12345), normalUserInfo.UserID, "用户ID应该匹配")
	assert.Equal(t, "test@example.com", normalUserInfo.Email, "邮箱应该匹配")
	assert.Equal(t, "normal-device", normalUserInfo.DeviceID, "设备ID应该匹配")

	// 测试4：过期token应该返回错误（要求重新登录）
	shortLivedManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		1*time.Millisecond, // 1毫秒后过期
		7*24*time.Hour,
		"test-issuer",
	)
	expiredTokenPair, err := shortLivedManager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond) // 等待token过期

	_, err = shortLivedManager.ExtractUserInfoWithGuest(ctx, "normal-device", expiredTokenPair.AccessToken)
	assert.Error(t, err, "过期token应该返回错误")

	// 测试5：设备ID不匹配应该返回错误（要求重新登录）
	_, err = manager.ExtractUserInfoWithGuest(ctx, "wrong-device", tokenPair.AccessToken)
	assert.Error(t, err, "设备ID不匹配应该返回错误")
	assert.Contains(t, err.Error(), "设备ID不匹配", "错误信息应该包含'设备ID不匹配'")

	// 测试6：空的 deviceId 应该返回错误
	_, err = manager.ExtractUserInfoWithGuest(ctx, "", "")
	assert.Error(t, err, "空的deviceId应该返回错误")
	assert.Contains(t, err.Error(), "设备ID不能为空", "错误信息应该包含'设备ID不能为空'")

	// 测试7：空的 deviceId 即使有有效token也应该返回错误
	_, err = manager.ExtractUserInfoWithGuest(ctx, "", tokenPair.AccessToken)
	assert.Error(t, err, "空的deviceId即使有有效token也应该返回错误")
	assert.Contains(t, err.Error(), "设备ID不能为空", "错误信息应该包含'设备ID不能为空'")

	t.Logf("游客模式测试通过")
}
