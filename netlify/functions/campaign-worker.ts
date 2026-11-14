import { runCampaignWorker } from "../../src/lib/server/campaign-worker";

export default async function campaignWorker() {
  const result = await runCampaignWorker(25_000);
  console.log("Campaign worker completed", result);
  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

export const config = {
  schedule: "* * * * *",
};
