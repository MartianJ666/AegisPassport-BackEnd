package io.aegis.passport.external;

/** Normalized identity returned only after a provider response is verified server-side. */
public record ExternalProviderIdentity(String provider, String issuer, String subject,
                                       String displayName, String avatar, String verifiedEmail) {}
