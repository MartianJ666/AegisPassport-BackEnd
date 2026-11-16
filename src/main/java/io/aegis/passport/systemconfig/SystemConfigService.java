package io.aegis.passport.systemconfig;

import io.aegis.passport.common.exception.BusinessException;
import io.aegis.passport.common.exception.ErrorCode;
import io.aegis.passport.systemconfig.entity.SystemConfig;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @RequiredArgsConstructor
public class SystemConfigService {
    private final SystemConfigRepository repo;
    private final JsonMapper json = new JsonMapper();
    public String get(String key,String fallback) { return repo.findByKey(key).map(SystemConfig::getValue).orElse(fallback); }
    public boolean allowMultipleDevices() { return Boolean.parseBoolean(get("security.session.allow-multiple-devices","true")); }
    @Transactional public void setAllowMultipleDevices(boolean allowed) { set("security.session.allow-multiple-devices",String.valueOf(allowed),"允许同时登录"); }
    @Transactional public void set(String key,String value,String description) {
        var cfg=repo.findByKey(key).orElseGet(()->{var c=new SystemConfig();c.setKey(key);return c;});
        cfg.setValue(value);if(description!=null)cfg.setDescription(description);repo.save(cfg);
    }
    public List<String> getBackgroundImages() {
        try { return json.readValue(get("login.background.images","[]"),new TypeReference<List<String>>() {}); }
        catch(Exception invalid) { return List.of(); }
    }
    public String getBackgroundMode() { return get("login.background.mode","color"); }
    public String getBackgroundColor() { return get("login.background.color","#FDF8FF"); }
    public int getBackgroundInterval() { try { return Math.max(3,Math.min(60,Integer.parseInt(get("login.background.interval","8")))); } catch(NumberFormatException invalid) { return 8; } }
    @Transactional public void saveBackground(List<String> images,String mode,Integer interval,String color) {
        if(images!=null && (images.size()>12 || images.stream().anyMatch(x->x==null || !x.matches("/uploads/backgrounds/[a-fA-F0-9-]+[.](jpg|png|gif|webp)"))))throw BusinessException.of(ErrorCode.BAD_REQUEST,"请选择已上传的背景图片，最多12张");
        if(mode!=null && !Set.of("color","single","carousel","random").contains(mode))throw BusinessException.of(ErrorCode.BAD_REQUEST,"背景模式无效");
        if(interval!=null && (interval<3 || interval>60))throw BusinessException.of(ErrorCode.BAD_REQUEST,"轮播间隔需为3至60秒");
        if(color!=null && !color.matches("#[a-fA-F0-9]{6}"))throw BusinessException.of(ErrorCode.BAD_REQUEST,"背景颜色无效");
        if(images!=null)set("login.background.images",json.writeValueAsString(new ArrayList<>(new LinkedHashSet<>(images))),null);
        if(mode!=null)set("login.background.mode",mode,null);
        if(interval!=null)set("login.background.interval",String.valueOf(interval),null);
        if(color!=null)set("login.background.color",color,null);
    }
}
