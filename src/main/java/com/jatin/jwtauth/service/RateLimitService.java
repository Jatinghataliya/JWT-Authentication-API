package com.jatin.jwtauth.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RateLimitService — in-memory per-IP token bucket rate limiter.
 *
 * Key learning points:
 *  1. Each unique key (IP address) gets its own Bucket with a fixed capacity.
 *  2. Bucket4j uses the token-bucket algorithm: tokens refill at a fixed rate.
 *  3. tryConsume(1) is non-blocking — it returns true if a token is available, false if not.
 *  4. For a distributed setup (multiple instances), replace ConcurrentHashMap with
 *     a Bucket4j ProxyManager backed by Redis or Hazelcast.
 *  5. Default config: 20 login attempts per minute per IP.
 *
 * Config properties (application.yml):
 *   app.rate-limit.capacity    — max burst (default 20)
 *   app.rate-limit.refill-per-minute — how many tokens refill per minute (default 10)
 */
@Slf4j
@Service
public class RateLimitService {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Value("${app.rate-limit.capacity:20}")
    private int capacity;

    @Value("${app.rate-limit.refill-per-minute:10}")
    private int refillPerMinute;

    /**
     * Returns true if the request is allowed (token consumed), false if rate-limited.
     *
     * @param key unique identifier — typically the client IP address
     */
    public boolean tryConsume(String key) {
        Bucket bucket = buckets.computeIfAbsent(key, this::newBucket);
        boolean allowed = bucket.tryConsume(1);
        if (!allowed) {
            log.warn("RateLimit: request denied for key='{}'", key);
        }
        return allowed;
    }

    /** Returns the number of available tokens for a given key (useful for tests). */
    public long getAvailableTokens(String key) {
        Bucket bucket = buckets.get(key);
        return bucket == null ? capacity : bucket.getAvailableTokens();
    }

    /** Clears all buckets — useful for test teardown. */
    public void reset() {
        buckets.clear();
    }

    private Bucket newBucket(String key) {
        Bandwidth limit = Bandwidth.classic(capacity,
                Refill.intervally(refillPerMinute, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }
}
