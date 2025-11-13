package middleware

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/kailun2047/slowmo/logging"
	"github.com/kailun2047/slowmo/proto"
	"github.com/kailun2047/slowmo/server"
	"github.com/redis/go-redis/v9"
)

const (
	envVarKeyRedisURL            = "REDIS_URL"
	envVarKeyGlobalTimeWindowSec = "GLOBAL_TIME_WINDOW"
	envVarKeyGlobalLimit         = "GLOBAL_LIMIT"
	envVarKeyUserTimeWindowSec   = "USER_TIME_WINDOW"
	envVarKeyUserLimit           = "USER_LIMIT"
)

type RedisRateLimiter struct {
	redisClient           *redis.Client
	createRedisClientOnce sync.Once
	globalTimeWindowSec   int
	globalLimit           int
	userTimeWindowSec     int
	userLimit             int
}

func NewRedisRateLimiter() *RedisRateLimiter {
	return &RedisRateLimiter{}
}

func getIntFromEnvVar(key string) int {
	valStr := os.Getenv(key)
	val, err := strconv.Atoi(valStr)
	if err != nil {
		logging.Logger().Fatalf("Invalid %s: [%s]", key, valStr)
	}
	return val
}

func (rl *RedisRateLimiter) getRedisClient() *redis.Client {
	rl.createRedisClientOnce.Do(func() {
		rl.globalTimeWindowSec = getIntFromEnvVar(envVarKeyGlobalTimeWindowSec)
		rl.globalLimit = getIntFromEnvVar(envVarKeyGlobalLimit)
		rl.userTimeWindowSec = getIntFromEnvVar(envVarKeyUserTimeWindowSec)
		rl.userLimit = getIntFromEnvVar(envVarKeyUserLimit)

		opts, err := redis.ParseURL(os.Getenv(envVarKeyRedisURL))
		if err != nil {
			logging.Logger().Fatal("invalid redis url")
		}
		rl.redisClient = redis.NewClient(opts)
	})
	return rl.redisClient
}

func formatLimitKey(prefix string, timeWindowSec int) string {
	now := time.Now().Unix()
	startOfTimeWindow := now - (now % int64(timeWindowSec))
	return fmt.Sprintf("%s-%d", prefix, startOfTimeWindow)
}

func (rl *RedisRateLimiter) CheckGlobalLimit(ctx context.Context) error {
	key := formatLimitKey("global_limt", rl.globalTimeWindowSec)
	return rl.checkRateLimit(ctx, key, rl.globalLimit, rl.globalTimeWindowSec)
}

func (rl *RedisRateLimiter) CheckUserLimit(ctx context.Context, user string, channel proto.AuthnChannel) error {
	key := formatLimitKey(fmt.Sprintf("%s-%v", user, channel), rl.userTimeWindowSec)
	return rl.checkRateLimit(ctx, key, rl.userLimit, rl.userTimeWindowSec)
}

func (rl *RedisRateLimiter) checkRateLimit(ctx context.Context, key string, limit, expSec int) error {
	pipe := rl.getRedisClient().Pipeline()
	inc := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Duration(expSec)*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		logging.Logger().Errorf("[Redis Rate Limiter] Limit check failed for key [%s]: %v", key, err)
		return server.ErrInternalExecution
	}
	if inc.Val() > int64(limit) {
		return server.ErrNoAvailableServer
	}
	return nil
}
