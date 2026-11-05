import { runCampaignWorker } from "../../src/lib/server/campaign-worker";

export default async function campaignWorker() {
  const result = await runCampaignWorker(25_000);
  console.log("Campaign worker completed", result);
  return result;
}

export const config = {
  schedule: "* * * * *",
};
