
// Vercel serverless function: POST /api/send-push
// Required Vercel environment variables:
// ONESIGNAL_REST_API_KEY
// ONESIGNAL_APP_ID
// FIREBASE_WEB_API_KEY
// ADMIN_UID

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      success: false,
      error: "Method not allowed. Use POST."
    });
  }

  const {
    ONESIGNAL_REST_API_KEY,
    ONESIGNAL_APP_ID,
    FIREBASE_WEB_API_KEY,
    ADMIN_UID
  } = process.env;

  const missing = [
    "ONESIGNAL_REST_API_KEY",
    "ONESIGNAL_APP_ID",
    "FIREBASE_WEB_API_KEY",
    "ADMIN_UID"
  ].filter(key => !process.env[key]);

  if (missing.length) {
    console.error(
      "send-push: missing environment variables:",
      missing.join(", ")
    );

    return res.status(500).json({
      success: false,
      error: "Server is not configured. Missing: " + missing.join(", ")
    });
  }

  let body = req.body;

  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = {};
    }
  }

  body = body || {};

  const {
    idToken,
    title,
    message,
    url,
    idempotencyKey
  } = body;

  if (!idToken || typeof idToken !== "string") {
    return res.status(401).json({
      success: false,
      error: "Missing Firebase ID token."
    });
  }

  if (
    !title ||
    !message ||
    typeof title !== "string" ||
    typeof message !== "string"
  ) {
    return res.status(400).json({
      success: false,
      error: "Both title and message are required."
    });
  }

  // 1. Verify Firebase administrator token
  let uid;

  try {
    const verify = await fetch(
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" +
        encodeURIComponent(FIREBASE_WEB_API_KEY),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ idToken })
      }
    );

    const verifyData = await verify.json().catch(() => ({}));

    if (
      !verify.ok ||
      !verifyData.users ||
      !verifyData.users[0]
    ) {
      console.warn(
        "send-push: token verification failed",
        verify.status,
        JSON.stringify(verifyData)
      );

      return res.status(401).json({
        success: false,
        error: "Invalid or expired sign-in. Please sign in again."
      });
    }

    uid = verifyData.users[0].localId;

  } catch (err) {
    console.error(
      "send-push: Identity Toolkit request failed:",
      err
    );

    return res.status(502).json({
      success: false,
      error: "Could not verify administrator sign-in."
    });
  }

  // 2. Verify administrator UID
  if (uid !== ADMIN_UID) {
    console.warn("send-push: rejected non-admin UID", uid);

    return res.status(403).json({
      success: false,
      error: "Only the administrator can send push notifications."
    });
  }

  // 3. Direct OneSignal subscription test
  const payload = {
    app_id: ONESIGNAL_APP_ID,

    include_subscription_ids: [
      "06074e3e-ae70-4005-9800-7ded8f2b61ce"
    ],

    headings: {
      en: title.slice(0, 120)
    },

    contents: {
      en: message.slice(0, 300)
    },

    url:
      typeof url === "string" &&
      /^https?:\/\//.test(url)
        ? url
        : undefined
  };

  if (
    typeof idempotencyKey === "string" &&
    idempotencyKey.length >= 8
  ) {
    payload.idempotency_key = idempotencyKey;
  }

  // 4. Send push notification
  try {
    const r = await fetch(
      "https://api.onesignal.com/notifications?c=push",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Accept": "application/json",
          "Authorization": "Key " + ONESIGNAL_REST_API_KEY
        },

        body: JSON.stringify(payload)
      }
    );

    const data = await r.json().catch(() => ({}));

    if (!r.ok || data.errors) {
      console.error(
        "send-push: OneSignal error",
        r.status,
        JSON.stringify(data)
      );

      return res.status(r.ok ? 422 : 502).json({
        success: false,
        error: "OneSignal could not send the notification.",
        details: data.errors || data
      });
    }

    console.info(
      "send-push: sent",
      data.id,
      "recipients:",
      data.recipients
    );

    return res.status(200).json({
      success: true,
      id: data.id,
      recipients: data.recipients
    });

  } catch (err) {
    console.error(
      "send-push: OneSignal request failed:",
      err
    );

    return res.status(502).json({
      success: false,
      error: "Could not reach OneSignal."
    });
  }
};
