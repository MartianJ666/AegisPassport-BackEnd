package io.aegis.passport.external;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.external.entity.ExternalIdentity;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/** User-facing management of bound third-party identities. */
@Service
@RequiredArgsConstructor
public class ExternalAccountService {
    private final ExternalIdentityRepository identities;
    private final UserRepository users;

    @Transactional(readOnly = true)
    public List<ExternalIdentity> listForUser(Long userId) {
        return identities.findByUserIdOrderByCreatedAtDesc(userId);
    }

    /** Binds an already-verified provider identity to a user. Global uniqueness enforced. */
    @Transactional
    public void bindToUser(Long userId, ExternalProviderIdentity external) {
        ExternalIdentity existing = identities.findByProviderAndIssuerAndProviderSubject(
                external.provider(), external.issuer(), external.subject()).orElse(null);
        if (existing != null) {
            if (!existing.getUser().getId().equals(userId)) {
                throw BusinessException.of(ErrorCode.EXTERNAL_IDENTITY_ALREADY_BOUND);
            }
            existing.setLastAuthenticatedAt(Instant.now());
            identities.save(existing);
            return;
        }
        User user = users.findById(userId).orElseThrow(() -> BusinessException.of(ErrorCode.USER_NOT_FOUND));
        identities.save(ExternalIdentity.builder().user(user).provider(external.provider())
                .issuer(external.issuer()).providerSubject(external.subject())
                .displayName(trim(external.displayName(), 100)).avatar(trim(external.avatar(), 500))
                .lastAuthenticatedAt(Instant.now()).build());
    }

    @Transactional
    public void unbind(Long userId, Long identityId) {
        ExternalIdentity identity = identities.findById(identityId)
                .orElseThrow(() -> BusinessException.of(ErrorCode.NOT_FOUND));
        if (!identity.getUser().getId().equals(userId)) {
            throw BusinessException.of(ErrorCode.NOT_FOUND);
        }
        identities.delete(identity);
    }

    private static String trim(String value, int limit) {
        if (!StringUtils.hasText(value)) return null;
        String text = value.trim();
        return text.length() <= limit ? text : text.substring(0, limit);
    }
}
