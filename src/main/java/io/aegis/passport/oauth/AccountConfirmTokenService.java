package io.aegis.passport.oauth;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Short-lived opaque tokens for the account-confirmation gate on every OAuth
 * authorize request. When a logged-in user starts an authorization, the backend
 * stashes the authorize URL (so the browser can return to it after confirming)
 * under a random token and redirects to the sso account-confirm page. Confirming
 * redirects back to the original authorize URL — the SAS flow then proceeds as
 * normal (silent code if consent already granted, otherwise the consent page).
 */
@Component
public class AccountConfirmTokenService {

    private static final long TTL_SECONDS = 300;

    /** One stashed confirmation request. */
    public record Entry(String authorizeUrl, String clientId, String username, Instant createdAt) {}

    private final Map<String, Entry> store = new ConcurrentHashMap<>();

    /** Create a token binding a client + username + original authorize URL. */
    public String create(String clientId, String username, String authorizeUrl) {
        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        store.put(token, new Entry(authorizeUrl, clientId, username, Instant.now()));
        return token;
    }

    /** Resolve a token; {@code null} if unknown or expired. */
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
        Entry entry = get(token);
        if (entry != null) {
            store.remove(token);
        }
        return entry;
    }

    /**
     * Periodic sweep so abandoned flows (tokens created but never resolved) cannot
     * grow the in-memory map without bound — the previous version only pruned
     * entries lazily on access, which a burst of abandoned authorizes could turn
     * into a slow memory leak.
     */
    @Scheduled(fixedRate = 60_000)
    public void prune() {
        Instant cutoff = Instant.now().minusSeconds(TTL_SECONDS);
        store.entrySet().removeIf(e -> e.getValue().createdAt().isBefore(cutoff));
    }
}
