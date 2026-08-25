// Nova (esclationsys) — send-mentor-push
//
// WHY THIS FILE EXISTS
// Sends a real Web Push notification (arrives even when the site isn't
// open — a system notification, same as any other app's push) to the
// OTHER participant of a mentor chat whenever a new row is inserted
// into `mentor_messages`. This is the server-side half of the feature;
// the client-side half (asking permission, subscribing, saving the
// subscription) lives in app.js / sw.js.
//
// This function does nothing on its own — it must be:
//   1. Deployed to your Supabase project (`supabase functions deploy`)
//   2. Given the VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY / VAPID_SUBJECT /
//      WEBHOOK_SECRET secrets (`supabase secrets set ...`)
//   3. Wired to a Database Webhook (Dashboard → Database → Webhooks)
//      that fires on INSERT into mentor_messages and calls this
//      function's URL, with the same WEBHOOK_SECRET as a custom header.
// See the deployment checklist sent alongside this file for the exact
// commands and dashboard steps — none of that can be done via SQL or
// from inside the repo, it has to happen in your Supabase project.
//
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically
// to every Edge Function by Supabase — they are NOT set manually here,
// and the service_role key never appears in client code (app.js only
// ever uses the public anon key).

import webpush from "npm:web-push@3.6.7";

const VAPID_PUBLIC_KEY = Deno.env.get("VAPID_PUBLIC_KEY")!;
const VAPID_PRIVATE_KEY = Deno.env.get("VAPID_PRIVATE_KEY")!;
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") || "mailto:admin@example.com";
const WEBHOOK_SECRET = Deno.env.get("WEBHOOK_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);

const dbHeaders = {
  apikey: SERVICE_ROLE_KEY,
  Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
  "Content-Type": "application/json",
};

Deno.serve(async (req) => {
  // Only the Database Webhook (which we configure with this same secret as a
  // custom header) is allowed to trigger a push — without this, the function's
  // public URL would let anyone spam arbitrary push payloads to any user.
  if (req.headers.get("x-webhook-secret") !== WEBHOOK_SECRET) {
    return new Response("unauthorized", { status: 401 });
  }

  let payload: any;
  try {
    payload = await req.json();
  } catch {
    return new Response("bad request", { status: 400 });
  }

  const message = payload?.record;
  if (!message || !message.request_id || !message.sender_email) {
    return new Response("ignored: no message record", { status: 200 });
  }

  try {
    const threadRes = await fetch(
      `${SUPABASE_URL}/rest/v1/mentor_requests?id=eq.${message.request_id}&select=trainee_email,mentor_email`,
      { headers: dbHeaders },
    );
    const threads = await threadRes.json();
    const thread = threads?.[0];
    if (!thread) return new Response("ignored: no thread", { status: 200 });

    const recipientEmail =
      thread.trainee_email === message.sender_email ? thread.mentor_email : thread.trainee_email;
    if (!recipientEmail) return new Response("ignored: no recipient", { status: 200 });

    const subsRes = await fetch(
      `${SUPABASE_URL}/rest/v1/push_subscriptions?user_email=eq.${encodeURIComponent(recipientEmail)}&select=endpoint,p256dh,auth`,
      { headers: dbHeaders },
    );
    const subs: Array<{ endpoint: string; p256dh: string; auth: string }> = await subsRes.json();
    if (!subs.length) return new Response("ok: no subscriptions", { status: 200 });

    const notificationPayload = JSON.stringify({
      title: "رسالة جديدة • New message",
      body: String(message.text || "").slice(0, 140),
      // Deep-links straight into this thread's chat — app.js reads this query param on
      // boot and opens the Mentorship chat directly instead of just landing on the home page.
      url: `/?mentorThread=${message.request_id}`,
      // Unique per message (not just per thread) — a shared tag makes the browser silently
      // replace the previous notification instead of alerting again, so only the first
      // message in a conversation would ever actually notify the recipient.
      tag: `mentor-message-${message.id}`,
    });

    await Promise.all(
      subs.map(async (s) => {
        try {
          await webpush.sendNotification(
            { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
            notificationPayload,
          );
        } catch (err: any) {
          // 404/410 means the browser dropped this subscription (uninstalled,
          // permission revoked, endpoint rotated) — clean it up so we stop
          // trying it on every future message.
          if (err?.statusCode === 404 || err?.statusCode === 410) {
            await fetch(
              `${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(s.endpoint)}`,
              { method: "DELETE", headers: dbHeaders },
            );
          }
        }
      }),
    );

    return new Response("ok", { status: 200 });
  } catch (e) {
    return new Response(`error: ${e}`, { status: 500 });
  }
});
