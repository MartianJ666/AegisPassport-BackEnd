package io.aegis.passport.client;

import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.user.entity.User;
import java.util.*;
import java.util.stream.Collectors;

/** Shared gate for authorize, consent and internal first-party checks. */
public final class ClientAccessPolicy {
    private ClientAccessPolicy() {}
    public static Set<String> csv(String value) {
        if(value==null || value.isBlank()) return new LinkedHashSet<>();
        return Arrays.stream(value.split(",")).map(String::trim).filter(s->!s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
    public static boolean organizationAllowed(OAuthClient client,Long organizationId) {
        String id=organizationId==null?null:organizationId.toString();
        if(id!=null && csv(client.getDeniedOrganizations()).contains(id))return false;
        return !client.isOrganizationRestricted() || (id!=null && csv(client.getAllowedOrganizations()).contains(id));
    }
    public static boolean allowed(OAuthClient client,User user,Collection<String> roles) {
        if(client==null || !client.isEnabled() || user==null || !user.isEnabled() || user.isLocked() || user.isBanned())return false;
        String id=String.valueOf(user.getId());
        if(csv(client.getDeniedUsers()).contains(id))return false;
        // Only administrators can manage this explicit override.
        if(individualGrantActive(client,id,java.time.Instant.now()))return true;
        if(!organizationAllowed(client,user.getOrganizationId()))return false;
        Set<String> wanted=csv(client.getAllowedRoles());
        return wanted.isEmpty() || (roles!=null && roles.stream().anyMatch(r->wanted.stream().anyMatch(r::equalsIgnoreCase)));
    }
    public static boolean allowed(OAuthClient client,User user) {
        return allowed(client,user,user==null || user.getRoles()==null?Set.of():user.getRoles().stream().map(r->r.getCode()).toList());
    }
    public static boolean individualGrantActive(OAuthClient client,String userId,java.time.Instant now) {
        if(!csv(client.getAllowedUsers()).contains(userId))return false;
        if(client.getAllowedUserExpirations()==null || !client.getAllowedUserExpirations().containsKey(userId))return true;
        Long expires=client.getAllowedUserExpirations().get(userId);
        return expires!=null && expires>now.toEpochMilli();
    }
}
