import type { UserSettings } from "@/types";

export const DEFAULT_SETTINGS: UserSettings = {
  defaultFromName: "",
  defaultFromEmail: "",
  defaultReplyTo: "",
  timezone: "UTC",
  trackOpens: true,
  trackClicks: true,
  autoAppendUnsubscribe: true,
  deliveryMethod: "gmail_app_password",
};
