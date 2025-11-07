package ratelimit

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

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
	globalTimeWindowStr := os.Getenv(envVarKeyGlobalTimeWindowSec)
	globalTimeWindowSec, err := strconv.Atoi(globalTimeWindowStr)
	if err != nil {
		log.Fatalf("Invalid global time window [%s]", globalTimeWindowStr)
	}
	globalLimitStr := os.Getenv(envVarKeyGlobalLimit)
	globalLimit, err := strconv.Atoi(globalLimitStr)
	if err != nil {
		log.Fatalf("Invalid global limit [%s]", globalLimitStr)
	}

	userTimeWindowStr := os.Getenv(envVarKeyUserTimeWindowSec)
	userTimeWindowSec, err := strconv.Atoi(userTimeWindowStr)
	if err != nil {
		log.Fatalf("Invalid user time window [%s]", userTimeWindowStr)
	}
	userLimitStr := os.Getenv(envVarKeyUserLimit)
	userLimit, err := strconv.Atoi(userLimitStr)
	if err != nil {
		log.Fatalf("Invalid user limit [%s]", userLimitStr)
	}

	return &RedisRateLimiter{
		globalTimeWindowSec: globalTimeWindowSec,
		globalLimit:         globalLimit,
		userTimeWindowSec:   userTimeWindowSec,
		userLimit:           userLimit,
	}
}

func (rl *RedisRateLimiter) getRedisClient() *redis.Client {
	rl.createRedisClientOnce.Do(func() {
		opts, err := redis.ParseURL(os.Getenv(envVarKeyRedisURL))
		if err != nil {
			log.Fatal("invalid redis url")
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
		log.Printf("[Redis Rate Limiter] Limit check failed for key [%s]: %v", key, err)
		return server.ErrInternalExecution
	}
	if inc.Val() > int64(limit) {
		return server.ErrNoAvailableServer
	}
	return nil
}
