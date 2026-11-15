import assert from "node:assert/strict";
import test from "node:test";
import {
  decideDuoAction,
  duoPushIsPending,
  extractDuoVerificationCode,
} from "./waterlooLogin.js";

const duoUrl = "https://example.duosecurity.com/frame/v4/auth/prompt";

test("declines every current and legacy trust-browser wording", () => {
  for (const label of [
    "No, do not trust browser",
    "No, do not trust this browser",
    "No, don't trust this browser",
    "No, other people use this device",
  ]) {
    assert.deepEqual(
      decideDuoAction({
        url: duoUrl,
        text: "Trust this browser? You won't need to log in as often from this browser.",
        controls: ["Yes, trust browser", label],
      }),
      { action: "decline_trust", label },
    );
  }

  assert.deepEqual(
    decideDuoAction({
      url: duoUrl,
      text: "Is this your device? Duo will remember it for future logins.",
      controls: ["Yes, this is my device", "No, other people use this device"],
    }),
    { action: "complete_trust", label: "Yes, this is my device" },
  );
});

test("prefers SMS/passcode and never selects Duo Push automatically", () => {
  assert.deepEqual(
    decideDuoAction({
      url: duoUrl,
      text: "Choose how to verify your identity",
      controls: ["Duo Push", "Text message passcode", "Duo Mobile passcode", "Security key"],
    }),
    { action: "select_sms_passcode", label: "Text message passcode" },
  );

  assert.deepEqual(
    decideDuoAction({
      url: duoUrl,
      text: "Choose how to verify your identity",
      controls: ["Duo Push", "Duo Mobile passcode", "Security key"],
    }),
    { action: "select_passcode", label: "Duo Mobile passcode" },
  );

  // Even if Duo Push is the only factor visible without Other options, never auto-push.
  for (const label of ["Duo Push", "Duo Push to iPhone", "Verify with Duo Push", "Send me a push"]) {
    assert.equal(
      decideDuoAction({
        url: duoUrl,
        text: "Choose how to verify your identity",
        controls: [label, "Security key"],
      }),
      null,
    );
  }
});

test("opens Other options from a passkey or passcode screen", () => {
  assert.deepEqual(
    decideDuoAction({
      url: duoUrl,
      text: "Use your security key to verify your identity",
      controls: ["Other options"],
    }),
    { action: "other_options", label: "Other options" },
  );
});

test("switches away from auto-push in interactive mode and stays inert in silent mode", () => {
  const state = {
    url: duoUrl,
    text: "Check for a Duo Push. Approve the request on your phone.",
    controls: ["Other options"],
  };
  assert.equal(duoPushIsPending(state), true);
  assert.equal(decideDuoAction(state, "silent"), null);
  assert.deepEqual(decideDuoAction(state, "interactive"), {
    action: "other_options",
    label: "Other options",
  });
  assert.equal(
    decideDuoAction({ url: duoUrl, text: state.text, controls: [] }, "interactive"),
    null,
  );
});

test("continues after Duo approval when Universal Prompt does not redirect", () => {
  assert.deepEqual(
    decideDuoAction({
      url: duoUrl,
      text: "Success! Your login request was approved.",
      controls: ["Continue"],
    }),
    { action: "continue_after_approval", label: "Continue" },
  );
});

test("ignores matching controls on non-Duo pages", () => {
  assert.equal(
    decideDuoAction({
      url: "https://learn.uwaterloo.ca/d2l/home",
      text: "Other options",
      controls: ["Duo Push"],
    }),
    null,
  );
});

test("extracts Verified Duo Push codes in compact and separated formats", () => {
  assert.equal(
    extractDuoVerificationCode({
      url: duoUrl,
      text: "Enter the verification code shown below in Duo Mobile: 417",
    }),
    "417",
  );
  assert.equal(
    extractDuoVerificationCode({
      url: duoUrl,
      text: "Verification code 8 0 3. Enter this code in your app.",
    }),
    "803",
  );
});

test("does not treat unrelated numbers as a Duo verification code", () => {
  assert.equal(
    extractDuoVerificationCode({
      url: duoUrl,
      text: "Duo Push sent. The request expires in 60 seconds. Copyright 2026.",
    }),
    null,
  );
  assert.equal(
    extractDuoVerificationCode({
      url: duoUrl,
      text: 'Sent to "Android" (•••-•••-7595). Sent to phone number ending in 7595.',
    }),
    null,
  );
  assert.equal(
    extractDuoVerificationCode({
      url: "https://learn.uwaterloo.ca/d2l/home",
      text: "Verification code 123",
    }),
    null,
  );
});
