package io.aegis.passport.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

/**
 * Caching for permission resolution and hot lookups. Uses Redis in docker and a
 * simple in-memory {@link ConcurrentMapCacheManager} locally so the app runs
 * without external services during development.
 */
@Configuration
public class CacheConfig {

    /** Effective-permission and role caches, keyed by user id. */
    public static final String RBAC_PERMISSIONS = "rbac:permissions";
    public static final String RBAC_ROLES = "rbac:roles";
    public static final String USER_BY_NAME = "userByName";
    public static final String CLIENT_BY_ID = "clientById";

    @Bean
    @ConditionalOnProperty(name = "passport.cache.provider", havingValue = "memory", matchIfMissing = true)
    public CacheManager memoryCacheManager() {
        // No explicit names → caches are created on demand, matching the Redis
        // manager's behaviour so both profiles resolve the same cache names.
        return new ConcurrentMapCacheManager();
    }

    @Bean
    @ConditionalOnProperty(name = "passport.cache.provider", havingValue = "redis")
    public CacheManager redisCacheManager(RedisConnectionFactory connectionFactory) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL);
        GenericJackson2JsonRedisSerializer serializer = new GenericJackson2JsonRedisSerializer(mapper);

        RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
                // the original Passport instance's cache on a shared Redis server.
                .computePrefixWith(name -> "aegis-passport::" + name + "::")
                .entryTtl(Duration.ofMinutes(30))
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(serializer));

        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(config)
                .build();
    }
}
