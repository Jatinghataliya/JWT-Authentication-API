package com.jatin.jwtauth.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.concurrent.TimeUnit;

/**
 * CacheConfig — configures a Caffeine (in-memory) CacheManager for environments
 * where Redis is not available (tests, local dev without Docker).
 *
 * Key learning points:
 *  1. When app.cache.type=caffeine, a Caffeine CacheManager is created.
 *  2. The @Primary annotation makes Caffeine the default when both beans
 *     could be present. In production with Redis, set app.cache.type=redis
 *     and Spring Data Redis will provide the CacheManager automatically.
 *  3. TTL is set to 5 minutes for cached data — suitable for user listings
 *     that change infrequently but shouldn't be stale for too long.
 *  4. Named caches are declared explicitly so Spring doesn't create them lazily
 *     with default settings.
 */
@Configuration
@ConditionalOnProperty(name = "app.cache.type", havingValue = "caffeine", matchIfMissing = true)
public class CacheConfig {

    @Bean
    @Primary
    public CacheManager caffeineCacheManager() {
        CaffeineCacheManager manager = new CaffeineCacheManager(
                "users",       // AdminService.getUserById / getAllUsers
                "auditEvents"  // AuditService.getEvents
        );
        manager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .maximumSize(500));
        return manager;
    }
}
