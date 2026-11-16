package io.aegis.passport.oauth;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Short-lived opaque tokens for the OAuth consent page. When SAS asks for
 * consent, the backend stashes the {@code client_id}/{@code scope}/{@code state}
 * under a random token and redirects the browser to the consent page with only
 * {@code ?token=…} — keeping client/scope/state out of the address bar. The
 * token is single-purpose, random (unguessable) and expires after
 * {@link #TTL_SECONDS}.
 */
@Component
public class ConsentTokenService {

    private static final long TTL_SECONDS = 300;

    /** One stashed consent request. */
    public record Entry(String clientId, List<String> scopes, String state, String username, Instant createdAt) {}

    private final Map<String, Entry> store = new ConcurrentHashMap<>();
    public void revoke(String token) { if (token != null) store.remove(token); }

    /** Create a token for a consent request and return the opaque value. */
    public String create(String clientId, List<String> scopes, String state, String username) {
        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        store.put(token, new Entry(clientId, scopes, state, username, Instant.now()));
        return token;
    }

    /** Resolve a token; {@code null} if unknown or expired (expired entries are pruned). */
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

    /**
     * Periodically prune expired entries. Wired to a scheduler so abandoned
     * consent flows cannot grow the map without bound — previously this method
     * existed but was never invoked, and entries were only removed lazily on
     * access.
     */
    @Scheduled(fixedRate = 60_000)
    public void prune() {
        Instant cutoff = Instant.now().minusSeconds(TTL_SECONDS);
        store.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
    }
}
