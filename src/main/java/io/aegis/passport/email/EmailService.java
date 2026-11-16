package io.aegis.passport.email;

import io.aegis.passport.email.entity.EmailConfig;
import jakarta.mail.internet.MimeMessage;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Sends transactional emails using the SMTP settings from the database.
 * Rebuilds the sender on each call (DB settings may change at runtime).
 * Uses async dispatch so the calling thread isn't blocked by SMTP latency.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailConfigRepository configRepo;

    /** Returns true when at least one enabled email config exists. */
    public boolean isEnabled() {
        return configRepo.findTopByOrderByIdAsc()
                .map(EmailConfig::isEnabled)
                .orElse(false);
    }

    @Async
    public void sendVerificationCode(String to, String code) {
        send(to, "Aegis Passport — 验证码", buildCodeBody(code));
    }

    @Async
    public void sendSessionVerificationCode(String to, String code) {
        send(to, "Aegis Passport — 设备管理验证码", "<p>您的登录设备管理验证码为：</p><h2 style='letter-spacing:4px'>" + code + "</h2><p>验证码 10 分钟内有效，请勿泄露给他人。</p>");
    }

    @Async
    public void sendDeviceOwnerRevocationCode(String to, String code) {
        send(to, "Aegis Passport — 设备所有者解绑验证码",
                "<p>您正在撤销本设备的设备所有者权限，验证码为：</p>"
                + "<h2 style='letter-spacing:4px'>" + code + "</h2>"
                + "<p>验证码 10 分钟内有效。如非本人操作请忽略本邮件。</p>");
    }

    public void sendTest(String to) {
        if (!send(to, "Aegis Passport — 邮件测试", "<p>SMTP 配置测试邮件，收到则表示配置正确。</p>"))
            throw io.aegis.passport.common.exception.BusinessException.of(io.aegis.passport.common.exception.ErrorCode.BAD_REQUEST, "测试邮件发送失败，请检查 SMTP 配置和服务器日志");
    }

    private boolean send(String to, String subject, String html) {
        Optional<EmailConfig> cfgOpt = configRepo.findTopByOrderByIdAsc();
        if (cfgOpt.isEmpty() || !cfgOpt.get().isEnabled()) {
            log.warn("[Email] 邮件服务未启用，跳过发送 to={}", to);
            return false;
        }
        EmailConfig cfg = cfgOpt.get();
        try {
            JavaMailSenderImpl sender = buildSender(cfg);
            MimeMessage msg = sender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, "UTF-8");
            helper.setFrom(cfg.getFromEmail(),
                    cfg.getFromName() != null ? cfg.getFromName() : "Aegis Passport");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(html, true);
            sender.send(msg);
            log.info("[Email] 发送成功 to={} subject={}", to, subject);
            return true;
        } catch (Exception e) {
            log.error("[Email] 发送失败 to={}: {}", to, e.getMessage());
            return false;
        }
    }

    private JavaMailSenderImpl buildSender(EmailConfig cfg) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(cfg.getSmtpHost());
        sender.setPort(cfg.getSmtpPort());
        sender.setUsername(cfg.getSmtpUsername());
        sender.setPassword(cfg.getSmtpPassword());
        java.util.Properties props = sender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        if (cfg.isUseTls()) {
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.ssl.trust", "*");
        }
        if (cfg.isUseSsl()) {
            props.put("mail.smtp.ssl.enable", "true");
        }
        return sender;
    }

    private String buildCodeBody(String code) {
        return "<p>您的 Aegis Passport 注册验证码为：</p>"
                + "<h2 style='letter-spacing:4px'>" + code + "</h2>"
                + "<p>验证码 10 分钟内有效，请勿泄露给他人。</p>";
    }
}
