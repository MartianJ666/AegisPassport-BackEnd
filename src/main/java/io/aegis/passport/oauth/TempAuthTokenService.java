package io.aegis.passport.oauth;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Short-lived opaque tokens that let a user authorize an OAuth client with a
 * DIFFERENT passport account than the one currently logged in (the "switch
 * account" flow). The backend verifies the target account's credentials, stashes
 * {@code clientId + targetUsername} under a random token, and a later
 * {@code /oauth2/authorize} request carrying that token is evaluated with the
 * target account's identity — without touching the main session.
 */
@Component
public class TempAuthTokenService {

    private static final long TTL_SECONDS = 300;

    /** One stashed temporary-identity request. */
    public record Entry(String clientId, String username, Instant createdAt) {}

    private final Map<String, Entry> store = new ConcurrentHashMap<>();

    /** Create a token binding a client to a target account and return it. */
    public String create(String clientId, String username) {
        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        store.put(token, new Entry(clientId, username, Instant.now()));
        return token;
    }

    /** Resolve a token; {@code null} if unknown or expired (expired entries pruned). */
    public Entry get(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        Entry entry = store.get(token);
        if (entry == null) {
            return null;
        }
        if (entry.createdAt().isBefore(Instant.now().minusSeconds(TTL_SECONDS))) {
            store.remove(token);
            return null;
        }
        return entry;
    }

    /** Consume a token so it can only be used once. */
    public Entry consume(String token) {
        if (token == null) return null;
        Entry entry = store.remove(token);
        return entry != null && !entry.createdAt().isBefore(Instant.now().minusSeconds(TTL_SECONDS)) ? entry : null;
    }

    /**
     * Periodic sweep for abandoned switches — tokens that were minted but never
     * carried on an authorize. Keeps the in-memory map bounded.
     */
    @Scheduled(fixedRate = 60_000)
    public void prune() {
        Instant cutoff = Instant.now().minusSeconds(TTL_SECONDS);
        store.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
    }
}
