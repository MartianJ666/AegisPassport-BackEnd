package io.aegis.passport.systemconfig;
import io.aegis.passport.audit.Audit;
import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.common.exception.*;
import io.aegis.passport.file.FileStorageService;
import io.aegis.passport.rbac.PermissionCatalog;
import io.aegis.passport.rbac.annotation.RequirePermission;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
@RestController @RequestMapping("/api/config") @RequiredArgsConstructor
public class SystemConfigController {
 private final SystemConfigService configService;
 private final FileStorageService files;
 @GetMapping("/login") public ResponseEntity<?> loginConfig() { return ResponseEntity.ok(ApiResult.ok(Map.of("backgroundImages",configService.getBackgroundImages(),"backgroundMode",configService.getBackgroundMode(),"backgroundInterval",configService.getBackgroundInterval(),"backgroundColor",configService.getBackgroundColor()))); }
 @PostMapping("/admin/login-background") @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
 @Audit(module="system",action="BACKGROUND_SAVE",description="保存登录背景")
 public ResponseEntity<?> save(@RequestBody Map<String,Object> body) {
  List<String> images=null;
  if(body.containsKey("backgroundImages")) {
   if(!(body.get("backgroundImages") instanceof List<?> list) || list.stream().anyMatch(x->!(x instanceof String)))throw BusinessException.of(ErrorCode.BAD_REQUEST);
   images=((List<?>)body.get("backgroundImages")).stream().map(String.class::cast).toList();
  }
  configService.saveBackground(images,body.get("backgroundMode") instanceof String s?s:null,body.get("backgroundInterval") instanceof Number n?n.intValue():null,body.get("backgroundColor") instanceof String s?s:null);
  return ResponseEntity.ok(ApiResult.ok());
 }
 @PostMapping("/admin/login-background/upload") @RequirePermission(PermissionCatalog.SYSTEM_CONFIG_EDIT)
 @Audit(module="system",action="BACKGROUND_UPLOAD",description="上传登录背景")
 public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) throws java.io.IOException {
  var images=new ArrayList<>(configService.getBackgroundImages());if(images.size()>=12)throw BusinessException.of(ErrorCode.BAD_REQUEST,"最多12张背景图片");
  String url=files.storeBackground(file);images.add(url);configService.saveBackground(images,null,null,null);
  return ResponseEntity.ok(ApiResult.ok(Map.of("url",url,"backgroundImages",images)));
 }
}
