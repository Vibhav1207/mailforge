import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import { sendEmailWithRetry } from "@/lib/email/provider";

export async function POST(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const body = await req.json();
    const { subject, htmlContent, textContent, fromName, fromEmail, replyTo, to, smtpConfig } = body;

    const targetRecipient = to || user.email;
    if (!targetRecipient) {
      return NextResponse.json({ error: "Missing recipient email address" }, { status: 400 });
    }

    const result = await sendEmailWithRetry({
      to: targetRecipient,
      subject: `[TEST] ${subject || "Email Preview"}`,
      html: htmlContent || "<p>This is a test email from MailForge.</p>",
      text: textContent,
      fromName: fromName || "MailForge Preview",
      fromEmail: fromEmail || smtpConfig?.user || user.email || "",
      replyTo,
      smtpConfig,
      variables: {
        firstName: user.name?.split(" ")[0] || "Recipient",
        lastName: user.name?.split(" ")[1] || "",
        company: "",
        email: targetRecipient,
      },
    });

    if (!result.success) {
      return NextResponse.json(
        { error: result.error || "Failed to deliver test message" },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      providerMessageId: result.providerMessageId,
      sentTo: targetRecipient,
    });
  } catch (err: any) {
    console.error("Send test route error:", err);
    return NextResponse.json(
      { error: err?.message || "Internal server error" },
      { status: 500 }
    );
  }
}
