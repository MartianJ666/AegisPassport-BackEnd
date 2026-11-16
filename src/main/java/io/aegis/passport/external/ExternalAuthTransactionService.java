package io.aegis.passport.external;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.external.entity.ExternalAuthTransaction;
import io.aegis.passport.user.entity.User;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor
public class ExternalAuthTransactionService {
    private static final long TTL_SECONDS = 300;
    private final ExternalAuthTransactionRepository repo;
    private final SecureRandom random = new SecureRandom();

    @Transactional
    public Start create(String provider, String pkceVerifier, String nonce, User user, String intent) {
        String id = random(24), state = random(24), browser = random(24);
        repo.save(ExternalAuthTransaction.builder().id(id).provider(provider).stateHash(hash(state))
                .browserHash(hash(browser)).pkceVerifier(pkceVerifier).nonce(nonce).user(user).intent(intent)
                .expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());
        return new Start(id, state, browser, pkceVerifier, nonce);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ExternalAuthTransaction consume(String provider, String id, String state, String browser) {
        ExternalAuthTransaction tx = repo.findLockedById(id).orElseThrow(ExternalAuthTransactionService::invalid);
        if (!provider.equals(tx.getProvider()) || tx.getConsumedAt() != null || tx.getExpiresAt().isBefore(Instant.now())
                || !same(tx.getStateHash(), hash(state)) || !same(tx.getBrowserHash(), hash(browser))) throw invalid();
        tx.setConsumedAt(Instant.now());
        return repo.saveAndFlush(tx);
    }

    @Scheduled(fixedRate = 300_000) @Transactional
    public void pruneExpired() { repo.deleteByExpiresAtBefore(Instant.now()); }

    public String random(int bytes) { byte[] raw = new byte[bytes]; random.nextBytes(raw); return Base64.getUrlEncoder().withoutPadding().encodeToString(raw); }
    private static boolean same(String a, String b) { return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8)); }
    private static String hash(String value) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (Exception e) { throw new IllegalStateException(e); } }
    private static BusinessException invalid() { return BusinessException.of(ErrorCode.BAD_REQUEST, "第三方登录状态无效或已过期"); }
    public record Start(String id, String state, String browser, String pkceVerifier, String nonce) {}
}
