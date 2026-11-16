package io.aegis.passport.client;

import io.aegis.passport.user.*;
import io.aegis.passport.user.entity.User;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.exception.*;
import java.time.Instant;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor
public class AdminAppAccessService {
 private final OAuthClientRepository clients;
 private final UserRepository users;
 public record View(String clientId,String clientName,String clientIcon,boolean enabled,String mode,Instant expiresAt,boolean expired,boolean organizationAllowed,boolean effectiveAllowed) {}
 private User user(Long id){return users.findById(id).orElseThrow(()->BusinessException.of(ErrorCode.USER_NOT_FOUND));}
 private View view(OAuthClient c,User u){
  String id=u.getId().toString();Long expiry=c.getAllowedUserExpirations()==null?null:c.getAllowedUserExpirations().get(id);
  boolean listed=ClientAccessPolicy.csv(c.getAllowedUsers()).contains(id),active=ClientAccessPolicy.individualGrantActive(c,id,Instant.now());
  String mode=ClientAccessPolicy.csv(c.getDeniedUsers()).contains(id)?"deny":active?"allow":"default";
  return new View(c.getClientId(),c.getClientName(),c.getClientIcon(),c.isEnabled(),mode,expiry==null?null:Instant.ofEpochMilli(expiry),listed&&!active,ClientAccessPolicy.organizationAllowed(c,u.getOrganizationId()),ClientAccessPolicy.allowed(c,u));
 }
 @Transactional(readOnly=true) public List<View> list(Long userId){var u=user(userId);return clients.findAllByOrderByCreatedAtDesc().stream().map(c->view(c,u)).toList();}
 @Transactional public View set(Long userId,String clientId,String mode,Integer hours){
  if(!Set.of("allow","deny","default").contains(mode) || (hours!=null && (hours<1 || hours>8760 || !mode.equals("allow"))))throw BusinessException.of(ErrorCode.BAD_REQUEST,"请选择放行、禁止或按规则；特批时长需 1-8760 小时");
  var u=user(userId);var c=clients.findForPolicyUpdate(clientId).orElseThrow(()->BusinessException.of(ErrorCode.CLIENT_NOT_FOUND));
  String id=userId.toString();var allowed=ClientAccessPolicy.csv(c.getAllowedUsers());var denied=ClientAccessPolicy.csv(c.getDeniedUsers());
  var expiry=new HashMap<String,Long>(c.getAllowedUserExpirations()==null?Map.of():c.getAllowedUserExpirations());
  allowed.remove(id);denied.remove(id);expiry.remove(id);
  if(mode.equals("allow")){allowed.add(id);if(hours!=null)expiry.put(id,Instant.now().plusSeconds(hours.longValue()*3600).toEpochMilli());}
  if(mode.equals("deny"))denied.add(id);
  String a=String.join(",",allowed),d=String.join(",",denied);
  if(a.length()>1000 || d.length()>1000)throw BusinessException.of(ErrorCode.BAD_REQUEST,"个人门禁人数超过当前应用限制");
  c.setAllowedUsers(a);c.setDeniedUsers(d);c.setAllowedUserExpirations(expiry);clients.saveAndFlush(c);
  return view(c,u);
 }
}
