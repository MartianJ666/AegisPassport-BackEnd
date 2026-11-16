package io.aegis.passport.apikey;

import java.time.Instant;

/** Safe API-key representation; never exposes secret hash or owner entity. */
public record ApiKeyView(Long id, String name, String apiKey, String scopes,
        boolean enabled, boolean adminDisabled, Instant expiresAt, Instant lastUsedAt,
        long useCount, Instant createdAt, Long ownerId, String ownerName) {
    public static ApiKeyView from(io.aegis.passport.apikey.entity.ApiKey key) {
        return new ApiKeyView(key.getId(), key.getName(), key.getApiKey(), key.getScopes(),
                key.isEnabled(), key.isAdminDisabled(), key.getExpiresAt(), key.getLastUsedAt(),
                key.getUseCount(), key.getCreatedAt(), key.getOwner() == null ? null : key.getOwner().getId(),
                key.getOwner() == null ? null : key.getOwner().getUsername());
    }
}
