package io.aegis.passport.file;

import io.aegis.passport.config.PassportProperties;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

/**
 * Stores user-uploaded files (avatars and client icons) under
 * the configured upload directory and returns a server-relative URL.
 */
@Service
@RequiredArgsConstructor
public class FileStorageService {

    private static final List<String> ALLOWED_IMAGE_TYPES = Arrays.asList(
            "image/jpeg", "image/png", "image/gif", "image/webp");

    private final PassportProperties props;

    public String storeBackground(MultipartFile file) throws IOException {
        validateImage(file, 10 * 1024 * 1024L);
        return store(file, "backgrounds", imageExtension(file.getContentType()));
    }

    public String storeAvatar(MultipartFile file) throws IOException {
        validateImage(file, 5 * 1024 * 1024L);
        return store(file, "avatars", imageExtension(file.getContentType()));
    }

    public String storeClientIcon(MultipartFile file) throws IOException {
        validateImage(file, 2 * 1024 * 1024L);
        return store(file, "icons", imageExtension(file.getContentType()));
    }

    /** MD5 of avatar file bytes (for change detection). */
    public String md5(MultipartFile file) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(md.digest(file.getBytes()));
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
    }

    private String store(MultipartFile file, String subdir, String extension) throws IOException {
        // Normalize and pin the destination under the upload dir so a crafted
        // extension can never escape it (defense in depth — the extension is
        // already derived from a whitelist in imageExtension()).
        Path dir = Paths.get(props.getUpload().getDir(), subdir).normalize().toAbsolutePath();
        Files.createDirectories(dir);
        String filename = UUID.randomUUID() + extension;
        Path dest = dir.resolve(filename).normalize();
        if (!dest.startsWith(dir)) {
            throw new IllegalArgumentException("非法文件名");
        }
        try (var stream = file.getInputStream()) {
            Files.copy(stream, dest, StandardCopyOption.REPLACE_EXISTING);
        }
        return props.getUpload().getUrlPrefix() + "/" + subdir + "/" + filename;
    }

    private void validateImage(MultipartFile file, long maxBytes) throws IOException {
        if (file.isEmpty()) throw new IllegalArgumentException("文件不能为空");
        if (file.getSize() > maxBytes) throw new IllegalArgumentException("文件超过大小限制");
        String ct = file.getContentType();
        if (ct == null || !ALLOWED_IMAGE_TYPES.contains(ct.toLowerCase())) {
            throw new IllegalArgumentException("仅支持 JPG/PNG/GIF/WebP 格式");
        }
        // Magic-byte check: the Content-Type header is client-controlled, so a
        // disguised HTML/JS payload must not pass as an "image".
        if (!matchesImageMagicBytes(file.getBytes()) || !imageExtension(ct).equals(detectedExtension(file.getBytes()))) {
            throw new IllegalArgumentException("文件内容与图片格式不符");
        }
    }

    /** True if the leading bytes match a real JPEG/PNG/GIF/WebP signature. */
    private static boolean matchesImageMagicBytes(byte[] b) {
        if (b == null || b.length < 12) return false;
        // JPEG: FF D8 FF
        if ((b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF) return true;
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if ((b[0] & 0xFF) == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47
                && b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A) return true;
        // GIF87a / GIF89a: 47 49 46 38
        if (b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38) return true;
        // WebP: RIFF....WEBP
        if (b[0] == 0x52 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x46
                && b[8] == 0x57 && b[9] == 0x45 && b[10] == 0x42 && b[11] == 0x50) return true;
        return false;
    }

    private static String detectedExtension(byte[] b) {
        if ((b[0] & 0xFF) == 0xFF) return ".jpg";
        if ((b[0] & 0xFF) == 0x89) return ".png";
        if (b[0] == 0x47) return ".gif";
        return ".webp";
    }

    private String imageExtension(String contentType) {
        return switch (contentType.toLowerCase()) {
            case "image/jpeg" -> ".jpg";
            case "image/png" -> ".png";
            case "image/gif" -> ".gif";
            case "image/webp" -> ".webp";
            default -> throw new IllegalArgumentException("仅支持 JPG/PNG/GIF/WebP 格式");
        };
    }
}
