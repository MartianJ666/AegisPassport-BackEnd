package io.aegis.passport.organization;

import io.aegis.passport.organization.entity.Organization;
import io.aegis.passport.client.*;
import io.aegis.passport.client.entity.OAuthClient;
import io.aegis.passport.common.exception.*;
import io.aegis.passport.user.*;
import io.aegis.passport.user.dto.UserDtos.UserView;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor
public class OrganizationService {
    private final OrganizationRepository organizations;
    private final UserRepository users;
    private final OAuthClientRepository clients;

    public record View(Long id,String name,String description,long userCount) {}
    public record AppView(String clientId,String clientName,boolean enabled,boolean restricted,boolean allowed) {}
    @Transactional(readOnly=true) public List<View> list() {
        return organizations.findAllByOrderByNameAsc().stream().map(o->new View(o.getId(),o.getName(),o.getDescription(),users.countByOrganizationId(o.getId()))).toList();
    }
    public Organization require(Long id) {
        return organizations.findById(id).orElseThrow(()->BusinessException.of(ErrorCode.BAD_REQUEST,"组织不存在，请刷新后重新选择"));
    }
    @Transactional public View save(Long id,String name,String description) {
        name=name==null?"":name.trim();
        if(name.isEmpty() || name.length()>100 || (description!=null && description.length()>255))throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织名称需 1-100 个字符，说明最多 255 个字符");
        if(id==null?organizations.existsByNameIgnoreCase(name):organizations.existsByNameIgnoreCaseAndIdNot(name,id))throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织名称已存在");
        Organization org=id==null?new Organization():require(id);
        org.setName(name);org.setDescription(description==null?null:description.trim());
        org=organizations.saveAndFlush(org);
        if(id!=null)users.renameOrganization(id,name);
        return new View(org.getId(),org.getName(),org.getDescription(),users.countByOrganizationId(org.getId()));
    }
    @Transactional public void delete(Long id) {
        Organization org=require(id);
        if(users.countByOrganizationId(id)>0)throw BusinessException.of(ErrorCode.BAD_REQUEST,"请先移出该组织的成员，再删除组织");
        String value=id.toString();
        if(clients.findAll().stream().anyMatch(c->ClientAccessPolicy.csv(c.getAllowedOrganizations()).contains(value)||ClientAccessPolicy.csv(c.getDeniedOrganizations()).contains(value)))
            throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织仍被应用访问规则引用，请先在应用中移除规则");
        organizations.delete(org);
    }
    @Transactional(readOnly=true) public List<UserView> members(Long id) {
        require(id);return users.findByOrganizationId(id).stream().map(UserView::from).toList();
    }
    @Transactional public void setMember(Long orgId,Long userId,boolean member) {
        Organization org=require(orgId);
        var user=users.findById(userId).orElseThrow(()->BusinessException.of(ErrorCode.USER_NOT_FOUND));
        if(member){user.setOrganizationId(orgId);user.setOrgName(org.getName());}
        else if(Objects.equals(user.getOrganizationId(),orgId)){user.setOrganizationId(null);user.setOrgName(null);}
        users.save(user);
    }
    @Transactional(readOnly=true) public List<AppView> apps(Long id) {
        require(id);return clients.findAllByOrderByCreatedAtDesc().stream().map(c->new AppView(c.getClientId(),c.getClientName(),c.isEnabled(),c.isOrganizationRestricted(),ClientAccessPolicy.organizationAllowed(c,id))).toList();
    }
    @Transactional public void setApps(Long id,Map<String,Boolean> changes) {
        require(id);
        if(changes==null || changes.size()>200 || changes.values().stream().anyMatch(Objects::isNull))throw BusinessException.of(ErrorCode.BAD_REQUEST,"应用访问设置无效");
        for(var entry:new TreeMap<>(changes).entrySet()) {
            OAuthClient c=clients.findForPolicyUpdate(entry.getKey()).orElseThrow(()->BusinessException.of(ErrorCode.CLIENT_NOT_FOUND));
            Set<String> allowed=ClientAccessPolicy.csv(c.getAllowedOrganizations()),denied=ClientAccessPolicy.csv(c.getDeniedOrganizations());
            String value=id.toString();
            if(entry.getValue()){denied.remove(value);if(c.isOrganizationRestricted())allowed.add(value);}
            else {allowed.remove(value);denied.add(value);}
            String a=String.join(",",allowed),d=String.join(",",denied);
            if(a.length()>1000||d.length()>1000)throw BusinessException.of(ErrorCode.BAD_REQUEST,"组织规则数量超过限制，请在应用中调整组织范围");
            c.setAllowedOrganizations(a);c.setDeniedOrganizations(d);clients.save(c);
        }
    }
}
