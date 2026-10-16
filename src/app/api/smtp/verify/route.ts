import { NextRequest, NextResponse } from "next/server";
import { verifyServerAuth, unauthorizedResponse } from "@/lib/firebase/auth-middleware";
import nodemailer, { Transporter } from "nodemailer";

export async function POST(req: NextRequest) {
  try {
    const user = await verifyServerAuth(req);
    if (!user) {
      return unauthorizedResponse();
    }

    const body = await req.json();
    const { host, port, user: smtpUser, pass: smtpPass, secure, isGmail } = body;

    const userToUse = (smtpUser || process.env.GMAIL_USER || process.env.SMTP_USER || "").trim();
    const rawPass = (smtpPass || process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASS || "").trim();
    // Google App Passwords often have spaces copied as "abcd efgh ijkl mnop", strip them
    const passToUse = rawPass.replace(/\s+/g, "");

    const isGmailService =
      Boolean(isGmail) ||
      (host && host.includes("gmail")) ||
      userToUse.toLowerCase().endsWith("@gmail.com");

    const hostToUse = host || (isGmailService ? "smtp.gmail.com" : process.env.SMTP_HOST);
    const portToUse = parseInt(port || (isGmailService ? "465" : process.env.SMTP_PORT || "587"), 10);
    const secureToUse = secure ?? (portToUse === 465 || process.env.SMTP_SECURE === "true");

    if (!userToUse || !passToUse) {
      return NextResponse.json(
        {
          error: "Missing credentials. Please provide your Gmail / SMTP email address and Google App Password.",
        },
        { status: 400 }
      );
    }

    let transporter: Transporter;

    if (isGmailService) {
      transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: userToUse,
          pass: passToUse,
        },
        connectionTimeout: 12000,
        greetingTimeout: 8000,
      });
    } else {
      transporter = nodemailer.createTransport({
        host: hostToUse,
        port: portToUse,
        secure: secureToUse,
        auth: {
          user: userToUse,
          pass: passToUse,
        },
        connectionTimeout: 12000,
        greetingTimeout: 8000,
      });
    }

    await transporter.verify();

    return NextResponse.json({
      success: true,
      message: isGmailService
        ? `Successfully connected to Gmail as ${userToUse}! Google App Password is authenticated and ready to dispatch emails.`
        : `Successfully connected to ${hostToUse}:${portToUse} as ${userToUse}. SMTP engine ready!`,
    });
  } catch (err: any) {
    console.error("SMTP verification error:", err);

    let friendlyError = err?.message || "Failed to verify credentials.";
    if (friendlyError.includes("535-5.7.8") || friendlyError.includes("Username and Password not accepted")) {
      friendlyError =
        "Google rejected the credentials. Please make sure: 1) You generated a 16-character App Password at myaccount.google.com/apppasswords, 2) 2-Step Verification is enabled on your Google Account, 3) Your Gmail address is typed correctly.";
    }

    return NextResponse.json(
      {
        error: friendlyError,
      },
      { status: 400 }
    );
  }
}
