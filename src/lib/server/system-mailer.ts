import { sendSingleEmail } from "@/lib/email/provider";
import { environmentSmtp } from "./settings";

export interface SystemEmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

/**
 * Dispatches system operational emails (email verification, password reset, security alerts)
 * using the server's configured environment SMTP / Gmail App Password, or logs securely in dev.
 */
export async function dispatchSystemEmail(options: SystemEmailOptions): Promise<{ success: boolean; error?: string }> {
  const fromEmail = process.env.EMAIL_FROM || process.env.FROM_EMAIL || "noreply@mailforge.app";
  const smtp = environmentSmtp();

  if (!smtp || !smtp.pass) {
    // In local development without configured SMTP, log message preview
    console.info(`[MailForge System Email Dev Preview] To: ${options.to} | Subject: ${options.subject}`);
    return { success: true };
  }

  try {
    const result = await sendSingleEmail({
      to: options.to,
      fromEmail,
      fromName: "MailForge Security",
      subject: options.subject,
      html: options.html,
      text: options.text,
      smtpConfig: smtp,
    });
    return result;
  } catch (err) {
    console.warn("System email delivery error:", (err as Error)?.message);
    return { success: false, error: (err as Error)?.message };
  }
}
