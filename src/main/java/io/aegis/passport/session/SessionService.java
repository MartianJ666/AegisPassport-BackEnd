package io.aegis.passport.session;

import io.aegis.passport.systemconfig.SystemConfigService;
import io.aegis.passport.user.UserRepository;
import io.aegis.passport.user.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SessionService {
    public static final String SESSION_ATTRIBUTE = "passport.session-id";
    public static final String DEVICE_HEADER = "X-Device-ID";
    private static final int ONLINE_SECONDS = 300;
    private final AuthSessionRepository repo;
    private final UserRepository users;
    private final SystemConfigService config;
    private final org.springframework.context.ApplicationEventPublisher events;
    public record RevokedSessions(List<String> sessionIds) {}

    @Transactional
    public AuthSession create(User user, HttpServletRequest request, String method) {
        Instant now = Instant.now();
        User locked = users.findById(user.getId()).orElseThrow();
        if (!config.allowMultipleDevices()) {
            var oldIds=repo.findByUser_IdOrderByLastSeenAtDesc(locked.getId()).stream().filter(s->s.isActiveAt(now)).map(AuthSession::getId).toList();
            repo.revokeActiveForUserExcept(locked.getId(), "__new__", now, "SINGLE_DEVICE_LOGIN", locked.getUsername());
            if(!oldIds.isEmpty())events.publishEvent(new RevokedSessions(oldIds));
        }
        AuthSession session = AuthSession.builder().id(UUID.randomUUID().toString()).user(locked).deviceHash(sha256(requireDeviceId(request)))
                .deviceLabel(deviceLabel(request)).ipAddress(clientIp(request)).userAgent(trim(request.getHeader("User-Agent"), 500))
                .authMethod(method).createdAt(now).lastSeenAt(now).expiresAt(now.plusMillis(604800000L)).build();
        AuthSession saved = repo.save(session);
        request.setAttribute(SESSION_ATTRIBUTE, saved.getId());
        request.getSession(true).setAttribute(SESSION_ATTRIBUTE, saved.getId());
        return saved;
    }
    @Transactional(readOnly = true)
    public boolean active(String id, Long userId) { return id != null && repo.isActive(id,userId,Instant.now()); }
    @Transactional
    public void touch(String id) { repo.findById(id).ifPresent(s -> { Instant now=Instant.now(); if(s.isActiveAt(now)&&s.getLastSeenAt().isBefore(now.minusSeconds(60))){s.setLastSeenAt(now);repo.save(s);} }); }
    @Transactional(readOnly = true)
    public List<SessionView> list(Long userId, String currentId) { Instant now=Instant.now(); Instant onlineAfter=now.minusSeconds(ONLINE_SECONDS); return repo.findByUser_IdOrderByLastSeenAtDesc(userId).stream().filter(s -> s.isActiveAt(now)).map(s -> new SessionView(s.getId(),s.getDeviceLabel(),maskIp(s.getIpAddress()),s.getCreatedAt(),s.getLastSeenAt(),s.getExpiresAt(),s.getRevokedAt(),s.getAuthMethod(),s.getLastSeenAt().isAfter(onlineAfter),Objects.equals(s.getId(),currentId))).toList(); }
    @Transactional public int revokeOwned(Long userId, Collection<String> ids, String actor, String reason) {
        var owned = repo.findByUser_IdOrderByLastSeenAtDesc(userId).stream().filter(s -> ids.contains(s.getId())).map(AuthSession::getId).toList();
        int count = owned.isEmpty() ? 0 : repo.revokeOwned(userId, owned, Instant.now(), reason, actor);
        if (count > 0) events.publishEvent(new RevokedSessions(owned));
        return count;
    }
    @Transactional public int deleteOwnedOffline(Long userId, Collection<String> ids) {
        Instant now = Instant.now(); int count = 0; List<String> removed = new ArrayList<>();
        for (String id : ids) {
            var session = repo.findById(id).filter(s -> s.getUser().getId().equals(userId)
                    && (!s.isActiveAt(now) || !s.getLastSeenAt().isAfter(now.minusSeconds(ONLINE_SECONDS))));
            if (session.isPresent()) { repo.delete(session.get()); removed.add(id); count++; }
        }
        if (!removed.isEmpty()) events.publishEvent(new RevokedSessions(removed));
        return count;
    }
    @Transactional public int revokeOtherSessions(Long userId,String exceptId,String actor) {
        var ids=repo.findByUser_IdOrderByLastSeenAtDesc(userId).stream().filter(s->!Objects.equals(exceptId,s.getId()) && s.isActiveAt(Instant.now())).map(AuthSession::getId).toList();
        return revokeOwned(userId,ids,actor,"PASSWORD_CHANGED");
    }
    @Transactional public int globalLogout(String currentSessionId, String actor) { return repo.revokeAllExcept(currentSessionId==null?"__none__":currentSessionId,Instant.now(),"ADMIN_GLOBAL_LOGOUT",actor); }
    public static String sessionId(HttpServletRequest request) { return request.getAttribute("passport.session-id") instanceof String s?s:null; }
    public static String requireDeviceId(HttpServletRequest r) { String v=r.getHeader(DEVICE_HEADER); return v!=null&&v.matches("[A-Za-z0-9_-]{20,100}")?v:UUID.randomUUID().toString().replace("-",""); }
    private static String sha256(String v){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    private static String clientIp(HttpServletRequest r){String x=r.getHeader("X-Forwarded-For");return x!=null&&!x.isBlank()?x.split(",")[0].trim():r.getRemoteAddr();}
    private static String deviceLabel(HttpServletRequest r){String u=trim(r.getHeader("User-Agent"),150);if(u==null)return "未知设备";if(u.contains("Android"))return "Android 浏览器";if(u.contains("iPhone")||u.contains("iPad"))return "iPhone/iPad 浏览器";if(u.contains("Windows"))return u.contains("Edg/")?"Windows Edge":u.contains("Firefox/")?"Windows Firefox":"Windows 浏览器";if(u.contains("Mac OS"))return "Mac 浏览器";return "浏览器设备";}
    private static String trim(String s,int n){return s==null?null:s.length()<=n?s:s.substring(0,n);}
    private static String maskIp(String ip){if(ip==null)return "-";int last=ip.lastIndexOf('.');return last>0?ip.substring(0,last)+".*":ip.length()>8?ip.substring(0,8)+"…":ip;}
    public record SessionView(String id,String deviceLabel,String ipAddress,Instant createdAt,Instant lastSeenAt,Instant expiresAt,Instant revokedAt,String authMethod,boolean online,boolean current) {}
}
