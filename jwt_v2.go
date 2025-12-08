package jwt

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type RedisClient interface {
	// Get 获取指定key的值
	Get(ctx context.Context, key string) (string, error)
	// Set 设置key-value，带过期时间
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	// Del 删除指定key
	Del(ctx context.Context, keys ...string) error
}

// TokenVersionCache 本地token版本缓存
type TokenVersionCache struct {
	cache sync.Map // key: userID:deviceID, value: cacheEntry
}

type cacheEntry struct {
	version   int64     // token版本号（时间戳）
	expiresAt time.Time // 缓存过期时间
}

// Get 获取缓存的token版本
func (c *TokenVersionCache) Get(key string) (int64, bool) {
	if val, ok := c.cache.Load(key); ok {
		entry := val.(cacheEntry)
		// 未过期
		if time.Now().Before(entry.expiresAt) {
			return entry.version, true
		}
		// 过期删除
		c.cache.Delete(key)
	}
	return 0, false
}

// Set 设置缓存的token版本
func (c *TokenVersionCache) Set(key string, version int64, ttl time.Duration) {
	c.cache.Store(key, cacheEntry{
		version:   version,
		expiresAt: time.Now().Add(ttl),
	})
}

// Delete 删除缓存
func (c *TokenVersionCache) Delete(key string) {
	c.cache.Delete(key)
}

// Clear 清空所有已过期的缓存
func (c *TokenVersionCache) Clear() {
	now := time.Now()
	c.cache.Range(func(key, value interface{}) bool {
		entry := value.(cacheEntry)
		if now.After(entry.expiresAt) {
			c.cache.Delete(key)
		}
		return true
	})
}

// JWTManagerV2 JWTService上增加互踢功能
type JWTManagerV2 struct {
	base           JWTService // 基础JWT服务（可以是JWTManager或其他实现）
	redis          RedisClient
	localCache     *TokenVersionCache
	enableKickOut  bool          // 是否启用互踢功能
	localCacheTTL  time.Duration // 本地缓存TTL=短token过期时间
	redisKeyPrefix string        // Redis key前缀
	accessExpiry   time.Duration // 访问令牌过期时间（从base获取）
	refreshExpiry  time.Duration // 刷新令牌过期时间（从base获取）
}

// JWTManagerV2Config V2配置
type JWTManagerV2Config struct {
	Base           JWTService    // 基础JWT服务（支持任何JWTService实现）
	Redis          RedisClient   // Redis客户端（如果enableKickOut=true则必填）
	EnableKickOut  bool          // 是否启用互踢
	LocalCacheTTL  time.Duration // 本地缓存TTL，默认=accessExpiry
	RedisKeyPrefix string        // Redis key前缀，默认="jwt:version:"
	AccessExpiry   time.Duration // 访问令牌过期时间（用于默认LocalCacheTTL）
	RefreshExpiry  time.Duration // 刷新令牌过期时间（用于Redis TTL）
}

// NewJWTManagerV2 创建增强版JWT管理器
func NewJWTManagerV2(config JWTManagerV2Config) (*JWTManagerV2, error) {
	if config.Base == nil {
		return nil, fmt.Errorf("base JWTService is required")
	}

	if config.EnableKickOut && config.Redis == nil {
		return nil, fmt.Errorf("redis client is required when enableKickOut is true")
	}

	// 默认本地缓存TTL = 访问令牌过期时间
	if config.LocalCacheTTL == 0 {
		if config.AccessExpiry > 0 {
			config.LocalCacheTTL = config.AccessExpiry
		} else {
			config.LocalCacheTTL = 30 * time.Minute
		}
	}

	if config.RefreshExpiry == 0 {
		config.RefreshExpiry = 7 * 24 * time.Hour // 默认7天
	}

	if config.RedisKeyPrefix == "" {
		config.RedisKeyPrefix = "jwt:version:"
	}

	v2 := &JWTManagerV2{
		base:           config.Base,
		redis:          config.Redis,
		localCache:     &TokenVersionCache{},
		enableKickOut:  config.EnableKickOut,
		localCacheTTL:  config.LocalCacheTTL,
		redisKeyPrefix: config.RedisKeyPrefix,
		accessExpiry:   config.AccessExpiry,
		refreshExpiry:  config.RefreshExpiry,
	}

	// 启动后台清理协程
	if config.EnableKickOut {
		go v2.startCacheCleaner()
	}

	return v2, nil
}

// GenerateToken 生成JWT令牌对
// 如果启用互踢，会生成新的token版本号并存储到Redis
func (v2 *JWTManagerV2) GenerateToken(ctx context.Context, claims *JWTClaims) (*JWTToken, error) {
	// 如果启用互踢，设置token版本号
	if v2.enableKickOut {
		// 使用纳秒级时间戳作为版本号，保证唯一性
		tokenVersion := time.Now().UnixNano()
		claims.TokenVersion = tokenVersion // 设置token版本号

		// 更新本地缓存
		cacheKey := v2.getCacheKey(claims.UserID, claims.DeviceID)
		v2.localCache.Set(cacheKey, tokenVersion, v2.localCacheTTL)

		// 存储到Redis
		key := v2.getRedisKey(claims.UserID, claims.DeviceID)
		err := v2.redis.Set(ctx, key, tokenVersion, v2.refreshExpiry)
		if err != nil {
			return nil, fmt.Errorf("failed to store token version to redis: %w", err)
		}
	}

	// 调用基础服务生成token
	return v2.base.GenerateToken(ctx, claims)
}

// ValidateToken 验证访问令牌
// 如果启用互踢，会检查token版本是否为最新
func (v2 *JWTManagerV2) ValidateToken(ctx context.Context, deviceId string, tokenString string) (*JWTClaims, error) {
	// 调用基础服务验证token
	claims, err := v2.base.ValidateToken(ctx, deviceId, tokenString)
	if err != nil {
		return nil, err
	}

	// 如果启用互踢，检查token版本
	if v2.enableKickOut {
		tokenVersion := claims.TokenVersion // 从TokenVersion字段读取token版本
		isValid, err := v2.checkTokenVersion(ctx, claims.UserID, claims.DeviceID, tokenVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to check token version: %w", err)
		}
		if !isValid {
			return nil, fmt.Errorf("token has been kicked out (old version)")
		}
	}

	return claims, nil
}

// RefreshToken 刷新令牌
func (v2 *JWTManagerV2) RefreshToken(ctx context.Context, deviceId string, refreshTokenString string, newClaims *JWTClaims) (*JWTToken, error) {
	// 如果启用互踢，生成新版本号
	if v2.enableKickOut {
		tokenVersion := time.Now().UnixNano()
		newClaims.TokenVersion = tokenVersion

		// 更新本地缓存
		cacheKey := v2.getCacheKey(newClaims.UserID, newClaims.DeviceID)
		v2.localCache.Set(cacheKey, tokenVersion, v2.localCacheTTL)

		// 存储到Redis
		key := v2.getRedisKey(newClaims.UserID, newClaims.DeviceID)
		err := v2.redis.Set(ctx, key, tokenVersion, v2.refreshExpiry)
		if err != nil {
			return nil, fmt.Errorf("failed to store new token version: %w", err)
		}
	}

	return v2.base.RefreshToken(ctx, deviceId, refreshTokenString, newClaims)
}

// ExtractUserInfo 从访问令牌中提取用户信息
func (v2 *JWTManagerV2) ExtractUserInfo(ctx context.Context, deviceId string, tokenString string) (UserInfo, error) {
	// 先验证token（包括版本检查）
	claims, err := v2.ValidateToken(ctx, deviceId, tokenString)
	if err != nil {
		return UserInfo{}, err
	}
	return claims.UserInfo, nil
}

// ExtractUserInfoWithGuest 支持游客模式：如果token为空返回游客信息，如果token存在则必须验证通过
// - 如果 deviceId 为空：返回错误（无效数据）
// - 如果 tokenString 为空：返回游客信息，不报错
// - 如果 tokenString 不为空但无效/过期/被踢出：返回错误，要求重新登录
// - 如果 tokenString 有效：返回用户信息
func (v2 *JWTManagerV2) ExtractUserInfoWithGuest(ctx context.Context, deviceId string, tokenString string) (UserInfo, error) {
	if deviceId == "" {
		return UserInfo{}, fmt.Errorf("设备ID不能为空")
	}

	// 如果token为空，直接返回游客信息
	if tokenString == "" {
		return v2.createGuestUserInfo(deviceId), nil
	}

	// token不为空，必须验证通过
	userInfo, err := v2.ExtractUserInfo(ctx, deviceId, tokenString)
	if err != nil {
		// token无效、过期、被踢出或验证失败，返回错误要求重新登录
		return UserInfo{}, err
	}

	// token有效，返回正常用户信息
	userInfo.IsGuest = false
	return userInfo, nil
}

// createGuestUserInfo 创建游客用户信息
func (v2 *JWTManagerV2) createGuestUserInfo(deviceId string) UserInfo {
	return UserInfo{
		UserID:   0, // 游客用户ID为0
		DeviceID: deviceId,
		IsGuest:  true,
	}
}

// KickOutDevice 主动踢出指定设备
func (v2 *JWTManagerV2) KickOutDevice(ctx context.Context, userID int64, deviceID string) error {
	if !v2.enableKickOut {
		return nil
	}

	// 将版本号设置为-1，表示该设备已被踢出
	// 不能直接删除key，因为删除后Redis查询失败会被误认为是Redis不可用而放过验证
	key := v2.getRedisKey(userID, deviceID)
	err := v2.redis.Set(ctx, key, -1, v2.refreshExpiry)
	if err != nil {
		return fmt.Errorf("failed to kick out device: %w", err)
	}

	// 更新本地缓存为-1
	cacheKey := v2.getCacheKey(userID, deviceID)
	v2.localCache.Set(cacheKey, -1, v2.localCacheTTL)

	return nil
}

// checkTokenVersion 检查token版本是否有效
func (v2 *JWTManagerV2) checkTokenVersion(ctx context.Context, userID int64, deviceID string, tokenVersion int64) (bool, error) {
	cacheKey := v2.getCacheKey(userID, deviceID)

	// 1、检查本地缓存
	if cachedVersion, found := v2.localCache.Get(cacheKey); found {
		// 已被踢出
		if cachedVersion == -1 {
			return false, nil
		}
		// 缓存命中且版本匹配
		if cachedVersion == tokenVersion {
			return true, nil
		}
	}

	// 2、查询Redis
	redisKey := v2.getRedisKey(userID, deviceID)
	versionStr, err := v2.redis.Get(ctx, redisKey)
	if err != nil {
		// Redis查询失败（可能是Redis宕机、网络超时等）
		// 为了服务可用性，选择降级放过，返回true，可用性更好，安全性差一点
		return true, nil
	}

	// 3、解析版本号
	var latestVersion int64
	_, err = fmt.Sscanf(versionStr, "%d", &latestVersion)
	if err != nil {
		return false, fmt.Errorf("invalid version format in redis: %w", err)
	}

	// 更新本地缓存
	v2.localCache.Set(cacheKey, latestVersion, v2.localCacheTTL)

	if latestVersion == -1 {
		return false, nil // 已被踢出
	}

	return latestVersion == tokenVersion, nil
}

// getRedisKey 生成Redis key
func (v2 *JWTManagerV2) getRedisKey(userID int64, deviceID string) string {
	return fmt.Sprintf("%s%d:%s", v2.redisKeyPrefix, userID, deviceID)
}

// getCacheKey 生成本地缓存key
func (v2 *JWTManagerV2) getCacheKey(userID int64, deviceID string) string {
	return fmt.Sprintf("%d:%s", userID, deviceID)
}

// startCacheCleaner 定期清理过期的本地缓存，防止内存泄漏
func (v2 *JWTManagerV2) startCacheCleaner() {
	// 每隔5分钟清理一次过期缓存
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		v2.localCache.Clear()
	}
}
