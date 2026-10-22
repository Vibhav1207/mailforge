import { NextRequest } from "next/server";
import { requireUser } from "@/lib/firebase/auth-middleware";
import { apiError, json } from "@/lib/server/api";
import { campaignRecipients } from "@/lib/server/campaigns";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireUser(req);
    return json({ recipients: await campaignRecipients(user.uid, (await params).id) });
  } catch (error) { return apiError(error); }
}
