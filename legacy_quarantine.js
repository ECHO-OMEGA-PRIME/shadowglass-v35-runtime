import legacy from "./original.js";

const headers = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

export default {
  async fetch() {
    return new Response(
      JSON.stringify({ migrated: true, service: "shadowglass-v35" }),
      { status: 410, headers },
    );
  },

  async queue(batch, env, ctx) {
    return legacy.queue(batch, env, ctx);
  },

  async scheduled() {
    // The grandfathered free account rejects Cron Trigger removal with error 10072.
    // Keep the trigger inert while the replacement systemd timer owns scheduling.
  },
};
