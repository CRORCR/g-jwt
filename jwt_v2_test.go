package jwt

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRedisClient Mock Redis客户端，用于测试
type MockRedisClient struct {
	data  sync.Map // key -> value
	mutex sync.Mutex
}

func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{}
}

func (m *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	if val, ok := m.data.Load(key); ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("key not found")
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	m.data.Store(key, fmt.Sprintf("%v", value))
	return nil
}

func (m *MockRedisClient) Del(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		m.data.Delete(key)
	}
	return nil
}

// TestJWTManagerV2_BasicFlow 测试V2基本流程
func TestJWTManagerV2_BasicFlow(t *testing.T) {
	// 创建基础管理器
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute, // 短token 30分钟
		7*24*time.Hour, // 长token 7天
		"test-issuer",
	)

	// 创建Mock Redis
	mockRedis := NewMockRedisClient()

	// 创建V2管理器，启用互踢
	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		Redis:         mockRedis,
		EnableKickOut: true,
		LocalCacheTTL: 30 * time.Minute,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 步骤1：用户在设备A登录，生成token
	claimsA := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   12345,
			Email:    "user@example.com",
			DeviceID: "device-A",
			Platform: "mac",
		},
	}

	tokenA, err := v2Manager.GenerateToken(ctx, claimsA)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenA.AccessToken)
	t.Logf("设备A的token: %s", tokenA.AccessToken[:50]+"...")

	// 步骤2：验证设备A的token（应该成功）
	validatedClaims, err := v2Manager.ValidateToken(ctx, "device-A", tokenA.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claimsA.UserID, validatedClaims.UserID)
	t.Log("✓ 设备A token验证成功")

	// 步骤3：用户在设备B登录，生成新token（会踢出设备A）
	claimsB := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   12345,
			Email:    "user@example.com",
			DeviceID: "device-A", // 同一个设备登录，覆盖旧token
			Platform: "mac",
		},
	}

	// 等待1纳秒，确保时间戳不同
	time.Sleep(1 * time.Microsecond)

	tokenB, err := v2Manager.GenerateToken(ctx, claimsB)
	require.NoError(t, err)
	t.Logf("设备A重新登录后的新token: %s", tokenB.AccessToken[:50]+"...")

	// 步骤4：验证旧token A（应该失败，因为被新token踢出）
	_, err = v2Manager.ValidateToken(ctx, "device-A", tokenA.AccessToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kicked out")
	t.Log("✓ 旧token被正确拒绝（互踢生效）")

	// 步骤5：验证新token B（应该成功）
	validatedClaimsB, err := v2Manager.ValidateToken(ctx, "device-A", tokenB.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claimsB.UserID, validatedClaimsB.UserID)
	t.Log("✓ 新token验证成功")
}

// TestJWTManagerV2_MultiDevice 测试多设备场景
func TestJWTManagerV2_MultiDevice(t *testing.T) {
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	mockRedis := NewMockRedisClient()

	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		Redis:         mockRedis,
		EnableKickOut: true,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 用户在设备A登录
	claimsA := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   99999,
			DeviceID: "device-A",
			Platform: "mac",
		},
	}
	tokenA, err := v2Manager.GenerateToken(ctx, claimsA)
	require.NoError(t, err)

	// 用户在设备B登录
	claimsB := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   99999,
			DeviceID: "device-B",
			Platform: "ios",
		},
	}
	tokenB, err := v2Manager.GenerateToken(ctx, claimsB)
	require.NoError(t, err)

	// 两个设备的token应该都有效（不同设备不互踢）
	_, err = v2Manager.ValidateToken(ctx, "device-A", tokenA.AccessToken)
	assert.NoError(t, err, "设备A的token应该有效")

	_, err = v2Manager.ValidateToken(ctx, "device-B", tokenB.AccessToken)
	assert.NoError(t, err, "设备B的token应该有效")

	t.Log("✓ 多设备同时在线正常工作")
}

// CountingRedisClient 统计调用次数的Redis客户端
type CountingRedisClient struct {
	inner    *MockRedisClient
	getCount int
	mutex    sync.Mutex
}

func (c *CountingRedisClient) Get(ctx context.Context, key string) (string, error) {
	c.mutex.Lock()
	c.getCount++
	c.mutex.Unlock()
	return c.inner.Get(ctx, key)
}

func (c *CountingRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.inner.Set(ctx, key, value, expiration)
}

func (c *CountingRedisClient) Del(ctx context.Context, keys ...string) error {
	return c.inner.Del(ctx, keys...)
}

func (c *CountingRedisClient) GetCount() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getCount
}

// TestJWTManagerV2_LocalCache 测试本地缓存效果
func TestJWTManagerV2_LocalCache(t *testing.T) {
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// 创建一个可以统计调用次数的Mock Redis
	countingRedis := &CountingRedisClient{
		inner: NewMockRedisClient(),
	}

	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		Redis:         countingRedis,
		EnableKickOut: true,
		LocalCacheTTL: 5 * time.Minute,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 生成token
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   88888,
			DeviceID: "test-device",
			Platform: "web",
		},
	}
	token, err := v2Manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 清空本地缓存，模拟缓存未命中的场景
	v2Manager.localCache.Delete(v2Manager.getCacheKey(claims.UserID, claims.DeviceID))
	t.Log("本地缓存已清空")

	// 连续验证10次同一个token
	for i := 0; i < 10; i++ {
		_, err = v2Manager.ValidateToken(ctx, "test-device", token.AccessToken)
		require.NoError(t, err)
	}

	// 检查Redis调用次数（应该只有第一次访问Redis，后续都命中本地缓存）
	getCount := countingRedis.GetCount()

	assert.Equal(t, 1, getCount, "应该只查询Redis一次，其他9次都命中本地缓存")
	t.Logf("✓ 本地缓存有效：10次验证只查询Redis %d次（首次未命中，后续全部命中）", getCount)
}

// TestJWTManagerV2_KickOutDevice 测试主动踢出设备
func TestJWTManagerV2_KickOutDevice(t *testing.T) {
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	mockRedis := NewMockRedisClient()

	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		Redis:         mockRedis,
		EnableKickOut: true,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 用户登录
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   77777,
			DeviceID: "device-to-kick",
			Platform: "android",
		},
	}
	token, err := v2Manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 验证token（应该成功）
	_, err = v2Manager.ValidateToken(ctx, "device-to-kick", token.AccessToken)
	require.NoError(t, err)
	t.Log("✓ token初始验证成功")

	// 主动踢出该设备
	err = v2Manager.KickOutDevice(ctx, 77777, "device-to-kick")
	require.NoError(t, err)
	t.Log("✓ 设备已被踢出")

	// 再次验证token（应该失败）
	_, err = v2Manager.ValidateToken(ctx, "device-to-kick", token.AccessToken)
	assert.Error(t, err)
	t.Log("✓ 被踢出后token验证失败")
}

// TestJWTManagerV2_WithoutKickOut 测试不启用互踢功能
func TestJWTManagerV2_WithoutKickOut(t *testing.T) {
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	// 不传Redis，不启用互踢
	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		EnableKickOut: false,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 生成token
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   66666,
			DeviceID: "device-X",
			Platform: "win",
		},
	}
	token, err := v2Manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 验证token（应该成功，不检查版本）
	_, err = v2Manager.ValidateToken(ctx, "device-X", token.AccessToken)
	require.NoError(t, err)

	// 再次生成token
	token2, err := v2Manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 两个token应该都有效（因为没有启用互踢）
	_, err = v2Manager.ValidateToken(ctx, "device-X", token.AccessToken)
	assert.NoError(t, err, "旧token应该仍然有效")

	_, err = v2Manager.ValidateToken(ctx, "device-X", token2.AccessToken)
	assert.NoError(t, err, "新token应该有效")

	t.Log("✓ 未启用互踢时，多个token可以共存")
}

// TestJWTManagerV2_RefreshToken 测试刷新token
func TestJWTManagerV2_RefreshToken(t *testing.T) {
	baseManager := NewJWTManager(
		"test-secret-key-for-jwt-signing-at-least-32-chars",
		30*time.Minute,
		7*24*time.Hour,
		"test-issuer",
	)

	mockRedis := NewMockRedisClient()

	v2Manager, err := NewJWTManagerV2(JWTManagerV2Config{
		Base:          baseManager,
		Redis:         mockRedis,
		EnableKickOut: true,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// 生成初始token
	claims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   55555,
			DeviceID: "refresh-test-device",
			Platform: "mac",
		},
	}
	oldToken, err := v2Manager.GenerateToken(ctx, claims)
	require.NoError(t, err)

	// 等待一下，确保时间戳不同
	time.Sleep(1 * time.Microsecond)

	// 刷新token
	newClaims := &JWTClaims{
		UserInfo: UserInfo{
			UserID:   55555,
			DeviceID: "refresh-test-device",
			Platform: "mac",
			IP:       "192.168.1.100", // 更新IP
		},
	}
	newToken, err := v2Manager.RefreshToken(ctx, "refresh-test-device", oldToken.RefreshToken, newClaims)
	require.NoError(t, err)

	// 旧的访问令牌应该失效
	_, err = v2Manager.ValidateToken(ctx, "refresh-test-device", oldToken.AccessToken)
	assert.Error(t, err, "刷新后旧访问令牌应该失效")

	// 新的访问令牌应该有效
	_, err = v2Manager.ValidateToken(ctx, "refresh-test-device", newToken.AccessToken)
	assert.NoError(t, err, "新访问令牌应该有效")

	t.Log("✓ token刷新后，旧token被正确踢出")
}
