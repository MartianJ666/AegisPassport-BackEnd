package io.aegis.passport.client;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.user.entity.User;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ClientAccessPolicyTests {
    private User user(){return User.builder().id(7L).username("member").organizationId(12L).build();}
    @Test void unconfiguredOrganizationGatePreservesRoleBehavior(){
        var c=OAuthClient.builder().allowedRoles("member,admin").build();
        assertTrue(ClientAccessPolicy.allowed(c,user(),Set.of("member")));
        assertFalse(ClientAccessPolicy.allowed(c,user(),Set.of("user")));
    }
    @Test void administratorGrantOverridesRolesAndOrganization(){
        var c=OAuthClient.builder().allowedRoles("admin").allowedUsers("7").organizationRestricted(true).allowedOrganizations("12").build();
        assertTrue(ClientAccessPolicy.allowed(c,user(),Set.of("user")));
        c.setAllowedOrganizations("13");assertTrue(ClientAccessPolicy.allowed(c,user(),Set.of("admin")));
    }
    @Test void organizationDoesNotGrantAdminRoleOrBypassRoleGate(){
        var c=OAuthClient.builder().allowedRoles("admin").organizationRestricted(true).allowedOrganizations("12").build();
        assertFalse(ClientAccessPolicy.allowed(c,user(),Set.of("member")));
    }
    @Test void denyListsWinAndMatchWholeIdentifiers(){
        var c=OAuthClient.builder().allowedUsers("7").allowedOrganizations("12").deniedOrganizations("12").build();
        assertTrue(ClientAccessPolicy.allowed(c,user(),Set.of("admin")));
        c.setDeniedOrganizations("112");assertTrue(ClientAccessPolicy.allowed(c,user(),Set.of()));
        c.setDeniedUsers("7");assertFalse(ClientAccessPolicy.allowed(c,user(),Set.of("admin")));
    }
    @Test void restrictedEmptyNeverBecomesAllowAllAndUnassignedAccountsAreDenied(){
        var c=OAuthClient.builder().organizationRestricted(true).allowedOrganizations("").build();
        assertFalse(ClientAccessPolicy.allowed(c,user(),Set.of("admin")));
        var u=user();u.setOrganizationId(null);c.setAllowedOrganizations("12");assertFalse(ClientAccessPolicy.allowed(c,u,Set.of("admin")));
    }
    @Test void disabledClientOrAccountCannotUseIndividualOverride(){
        var c=OAuthClient.builder().allowedUsers("7").enabled(false).build();var u=user();
        assertFalse(ClientAccessPolicy.allowed(c,u,Set.of("admin")));
        c.setEnabled(true);u.setEnabled(false);assertFalse(ClientAccessPolicy.allowed(c,u,Set.of("admin")));
        u.setEnabled(true);u.setLocked(true);assertFalse(ClientAccessPolicy.allowed(c,u,Set.of("admin")));
        u.setLocked(false);u.setBannedUntil(java.time.Instant.now().plusSeconds(60));assertFalse(ClientAccessPolicy.allowed(c,u,Set.of("admin")));
    }
}
