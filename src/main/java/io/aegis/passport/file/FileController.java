package io.aegis.passport.file;

import io.aegis.passport.common.api.ApiResult;
import io.aegis.passport.security.SecurityUtils;
import io.aegis.passport.user.UserService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/** File upload endpoints for avatars and client icons. */
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    private final FileStorageService storage;
    private final UserService userService;

    @PostMapping("/avatar")
    public ResponseEntity<ApiResult<Map<String, String>>> uploadAvatar(
            @RequestParam("file") MultipartFile file) throws Exception {
        String url = storage.storeAvatar(file);
        String md5 = storage.md5(file);
        userService.updateAvatar(SecurityUtils.currentUsername(), url, md5);
        return ResponseEntity.ok(ApiResult.ok(Map.of("url", url, "md5", md5)));
    }
}
