import * as NodeServices from "@effect/platform-node/NodeServices";
import { describe, expect, it } from "@effect/vitest";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Path from "effect/Path";
import { FetchHttpClient, HttpClient, HttpClientResponse } from "effect/http";

import { makeAntigravityUsageProbe } from "./antigravityUsageLimits.ts";

const summary = {
  groups: [
    {
      displayName: "Gemini Models",
      buckets: [
        {
          bucketId: "gemini-weekly",
          window: "weekly",
          remainingFraction: 0.96,
          resetTime: "2026-10-12T19:41:43Z",
        },
        {
          bucketId: "gemini-5h",
          window: "5h",
          remainingFraction: 0.91,
          resetTime: "2026-10-09T16:06:01Z",
        },
      ],
    },
    {
      displayName: "Claude and GPT models",
      buckets: [
        {
          bucketId: "3p-weekly",
          window: "weekly",
          remainingFraction: 0,
          resetTime: "2026-10-10T15:28:22Z",
        },
        {
          bucketId: "3p-5h",
          window: "5h",
          remainingFraction: 0.44,
          resetTime: "2026-10-09T16:06:30Z",
        },
      ],
    },
  ],
};

const fixture = Effect.fn("AntigravityUsageTest.fixture")(function* (
  options: {
    summary?: unknown;
    models?: unknown;
    summaryStatus?: number;
    summaries?: Array<{ body: unknown; status?: number }>;
    tokenStatus?: number;
    refreshToken?: string;
    /** Google account id from userinfo; omit to make userinfo fail. */
    userId?: string;
    missingToken?: boolean;
    authMethod?: "oauth-personal" | "gemini-api-key";
  } = {},
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const profileDirectory = yield* fs.makeTempDirectoryScoped();
  yield* fs.makeDirectory(path.join(profileDirectory, "antigravity-acp"));
  const tokenPath = path.join(profileDirectory, "antigravity-acp", "acp_token.json");
  const writeToken = (refreshToken: string) =>
    fs.writeFileString(
      tokenPath,
      JSON.stringify({
        client_id: "client-id",
        client_secret: "client-secret",
        refresh_token: refreshToken,
        project_id: "project-id",
      }),
    );
  if (!options.missingToken) yield* writeToken(options.refreshToken ?? "refresh-a");
  const requests: Array<{ url: string; body: string }> = [];
  const http = HttpClient.make((request, _url, _signal, fiber) =>
    Effect.sync(() => {
      const init = Context.getOrUndefined(fiber.context, FetchHttpClient.RequestInit);
      expect(init?.redirect).toBe("manual");
      const body =
        request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
      requests.push({ url: request.url, body });
      if (request.url.endsWith("/token")) {
        expect(new URLSearchParams(body).get("grant_type")).toBe("refresh_token");
        return HttpClientResponse.fromWeb(
          request,
          Response.json(
            { access_token: "access-token", expires_in: 3600 },
            { status: options.tokenStatus ?? 200 },
          ),
        );
      }
      expect(request.headers.authorization).toBe("Bearer access-token");
      if (request.url.endsWith("/userinfo")) {
        return HttpClientResponse.fromWeb(
          request,
          options.userId
            ? Response.json({ id: options.userId, email: "someone@example.com" })
            : Response.json({}, { status: 403 }),
        );
      }
      expect(JSON.parse(body)).toEqual({ project: "project-id" });
      expect(request.headers["user-agent"]).toMatch(/^antigravity\/cli\/1\.4\.0 /);
      expect(request.url.startsWith("https://daily-cloudcode-pa.googleapis.com/")).toBe(true);
      const nextSummary = request.url.endsWith(":retrieveUserQuotaSummary")
        ? options.summaries?.shift()
        : undefined;
      return HttpClientResponse.fromWeb(
        request,
        request.url.endsWith(":retrieveUserQuotaSummary")
          ? Response.json(nextSummary?.body ?? options.summary ?? summary, {
              status: nextSummary?.status ?? options.summaryStatus ?? 200,
            })
          : Response.json(options.models ?? { models: {} }),
      );
    }),
  );
  const usage = yield* makeAntigravityUsageProbe({
    profileDirectory,
    authMethod: options.authMethod ?? "oauth-personal",
  }).pipe(Effect.provideService(HttpClient.HttpClient, http));
  return { ...usage, requests, writeToken, tokenPath };
});

describe("Antigravity subscription limits", () => {
  it.effect("reports separate Gemini and shared Claude/GPT five-hour and weekly limits", () =>
    Effect.gen(function* () {
      const { probe, requests } = yield* fixture();
      const limits = yield* probe;
      expect(limits.windows).toHaveLength(4);
      expect(limits.unavailable).toBeUndefined();
      expect(limits.credentialFingerprint).toMatch(/^[0-9a-f]{64}$/);
      const byId = new Map(limits.windows.map((window) => [window.id, window]));
      expect(byId.get("gemini-weekly")?.usedPercent).toBeCloseTo(4);
      expect(byId.get("gemini-5h")?.usedPercent).toBeCloseTo(9);
      expect(byId.get("3p-weekly")).toMatchObject({
        label: "Claude & GPT (shared) · Weekly",
        kind: "weekly",
        usedPercent: 100,
        windowDurationMins: 10080,
        resetsAt: "2026-10-10T15:28:22.000Z",
      });
      expect(byId.get("3p-5h")).toMatchObject({ kind: "session", windowDurationMins: 300 });
      expect(byId.get("3p-5h")?.usedPercent).toBeCloseTo(56);
      yield* probe;
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(1);
      expect(
        requests.filter((request) => request.url.endsWith(":retrieveUserQuotaSummary")),
      ).toHaveLength(2);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect(
    "reports CLI Gemini quotas for both idle accounts and Argon only for the entitled account",
    () =>
      Effect.gen(function* () {
        const first = yield* fixture({
          userId: "account-a",
          summary: {
            groups: [
              {
                buckets: [
                  { bucketId: "gemini-weekly", remainingFraction: 0.992 },
                  { bucketId: "gemini-5h", remainingFraction: 0.972 },
                  { bucketId: "3p-weekly", remainingFraction: 0.507 },
                  { bucketId: "3p-5h", remainingFraction: 1 },
                  { bucketId: "gemini-argon-wtu-weekly", remainingFraction: 1 },
                ],
              },
            ],
          },
        });
        const second = yield* fixture({ userId: "account-b" });
        const a = yield* first.probe;
        const b = yield* second.probe;
        expect(a.credentialFingerprint).not.toBe(b.credentialFingerprint);
        expect(a.windows).toHaveLength(5);
        expect(b.windows).toHaveLength(4);
        expect(a.windows.find((window) => window.id === "gemini-weekly")?.usedPercent).toBeCloseTo(
          0.8,
        );
        expect(a.windows.find((window) => window.id === "gemini-5h")?.usedPercent).toBeCloseTo(2.8);
        expect(a.windows.find((window) => window.id === "gemini-argon-wtu-weekly")).toMatchObject({
          label: "Gemini Argon WTU · Weekly",
          usedPercent: 0,
        });
        expect(b.windows.some((window) => window.id.includes("argon"))).toBe(false);
        expect((yield* first.probe).windows).toEqual(a.windows);
        expect((yield* second.probe).windows).toEqual(b.windows);
      }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect(
    "reports probe failure on a temporary summary error instead of replacing CLI quotas with another source",
    () =>
      Effect.gen(function* () {
        const { probe, requests } = yield* fixture({
          summaries: [{ body: summary }, { body: {}, status: 503 }, { body: summary }],
          models: { models: { "gemini-a": { quotaInfo: { remainingFraction: 1 } } } },
        });
        expect((yield* probe).windows).toHaveLength(4);
        expect((yield* probe).unavailable?.reason).toBe("probeFailed");
        expect((yield* probe).windows).toHaveLength(4);
        expect(
          requests.filter((request) => request.url.endsWith(":fetchAvailableModels")),
        ).toHaveLength(0);
        expect(
          requests.every(
            (request) => !request.url.startsWith("https://cloudcode-pa.googleapis.com"),
          ),
        ).toBe(true);
      }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("labels an account's extra Gemini pool as its own row and keeps the generic rows", () =>
    Effect.gen(function* () {
      const { probe } = yield* fixture({
        summary: {
          buckets: [
            { bucketId: "gemini-weekly", window: "weekly", remainingFraction: 1 },
            { bucketId: "gemini-5h", window: "5h", remainingFraction: 0.5 },
            { bucketId: "gemini-argon-wtu-weekly", window: "weekly", remainingFraction: 0.25 },
          ],
        },
      });
      const limits = yield* probe;
      expect(
        Object.fromEntries(
          limits.windows.map((window) => [window.id, [window.label, window.usedPercent]]),
        ),
      ).toEqual({
        "gemini-weekly": ["Gemini · Weekly", 0],
        "gemini-5h": ["Gemini · 5-hour", 50],
        "gemini-argon-wtu-weekly": ["Gemini Argon WTU · Weekly", 75],
      });
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("takes the window length from the bucket id when the bucket omits it", () =>
    Effect.gen(function* () {
      const { probe } = yield* fixture({
        summary: {
          buckets: [
            { bucketId: "gemini-argon-wtu-weekly", remainingFraction: 0.4 },
            { bucketId: "gemini-5h", remainingFraction: 0.4 },
            { bucketId: "gemini-other-pool", displayName: "Burst", remainingFraction: 0.4 },
          ],
        },
      });
      const byId = new Map((yield* probe).windows.map((window) => [window.id, window]));
      expect(byId.get("gemini-argon-wtu-weekly")).toMatchObject({
        kind: "weekly",
        windowDurationMins: 10080,
      });
      expect(byId.get("gemini-5h")).toMatchObject({ kind: "session", windowDurationMins: 300 });
      expect(byId.get("gemini-other-pool")).toMatchObject({
        label: "Gemini Other Pool · Burst",
        kind: "other",
      });
      expect(byId.get("gemini-other-pool")?.windowDurationMins).toBeUndefined();
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("reports only the buckets each account returns, without placeholders", () =>
    Effect.gen(function* () {
      const withPool = yield* fixture({
        summary: {
          buckets: [
            { bucketId: "gemini-weekly", window: "weekly", remainingFraction: 1 },
            { bucketId: "gemini-argon-wtu-weekly", window: "weekly", remainingFraction: 0.5 },
          ],
        },
      });
      const withoutPool = yield* fixture({
        summary: {
          buckets: [{ bucketId: "gemini-weekly", window: "weekly", remainingFraction: 0.9 }],
        },
      });
      const first = yield* withPool.probe;
      const second = yield* withoutPool.probe;
      expect(first.windows.map((window) => window.id).toSorted()).toEqual([
        "gemini-argon-wtu-weekly",
        "gemini-weekly",
      ]);
      expect(second.windows.map((window) => window.id)).toEqual(["gemini-weekly"]);
      expect(second.unavailable).toBeUndefined();
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("re-reads changed credentials and clears cached access after sign-out", () =>
    Effect.gen(function* () {
      const { probe, clear, requests, writeToken, tokenPath } = yield* fixture();
      const first = yield* probe;
      yield* writeToken("refresh-b");
      const second = yield* probe;
      // Without a readable Google account, the credential itself names the account.
      expect(second.credentialFingerprint).not.toBe(first.credentialFingerprint);
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(2);
      yield* (yield* FileSystem.FileSystem).remove(tokenPath);
      expect((yield* probe).unavailable?.reason).toBe("unsupported");
      yield* writeToken("refresh-b");
      yield* probe;
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(3);
      yield* clear;
      yield* probe;
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(4);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("names one Google account the same way from every sign-in", () =>
    Effect.gen(function* () {
      const read = (refreshToken: string, userId: string) =>
        fixture({ refreshToken, userId }).pipe(Effect.flatMap((usage) => usage.probe));
      const machineA = yield* read("refresh-a", "google-user-1");
      const machineB = yield* read("refresh-b", "google-user-1");
      const otherAccount = yield* read("refresh-c", "google-user-2");
      expect(machineA.credentialFingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(machineB.credentialFingerprint).toBe(machineA.credentialFingerprint);
      expect(otherAccount.credentialFingerprint).not.toBe(machineA.credentialFingerprint);
      expect(JSON.stringify(machineA)).not.toMatch(/google-user-1|someone@example.com/);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("falls back to model quotas without inventing a window duration", () =>
    Effect.gen(function* () {
      const { probe } = yield* fixture({
        summary: { groups: [] },
        models: {
          models: {
            "gemini-a": {
              modelProvider: "MODEL_PROVIDER_GOOGLE",
              quotaInfo: { remainingFraction: 0.8, resetTime: "2026-10-10T12:00:00Z" },
            },
            "gemini-b": {
              modelProvider: "MODEL_PROVIDER_GOOGLE",
              quotaInfo: { remainingFraction: 0.6, resetTime: "2026-10-10T12:00:00Z" },
            },
            "claude-a": { quotaInfo: { remainingFraction: 0.2 } },
          },
        },
      });
      const limits = yield* probe;
      expect(limits.windows).toHaveLength(2);
      expect(limits.windows.find((window) => window.id === "gemini-quota")?.usedPercent).toBe(40);
      expect(
        limits.windows.every(
          (window) => window.kind === "other" && window.windowDurationMins === undefined,
        ),
      ).toBe(true);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("skips disabled and missing fractions and clamps valid percentages", () =>
    Effect.gen(function* () {
      const { probe } = yield* fixture({
        summary: {
          buckets: [
            { bucketId: "disabled", remainingFraction: 0, disabled: true },
            { bucketId: "missing", resetTime: "2026-10-10T12:00:00Z" },
            { bucketId: "gemini-5h", window: "5h", remainingFraction: 2, resetTime: "invalid" },
          ],
        },
      });
      expect((yield* probe).windows).toEqual([
        {
          id: "gemini-5h",
          kind: "session",
          label: "Gemini · 5-hour",
          usedPercent: 0,
          windowDurationMins: 300,
        },
      ]);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("preserves cached access token when quota endpoints return no usable windows", () =>
    Effect.gen(function* () {
      const { probe, requests } = yield* fixture({
        summary: { groups: [] },
        models: { models: {} },
      });
      const first = yield* probe;
      expect(first.unavailable?.reason).toBe("probeFailed");
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(1);
      const second = yield* probe;
      expect(second.unavailable?.reason).toBe("probeFailed");
      expect(requests.filter((request) => request.url.endsWith("/token"))).toHaveLength(1);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("returns a safe failure when OAuth refresh fails", () =>
    Effect.gen(function* () {
      const { probe } = yield* fixture({ tokenStatus: 401 });
      const limits = yield* probe;
      expect(limits.windows).toEqual([]);
      expect(limits.unavailable?.reason).toBe("probeFailed");
      expect(JSON.stringify(limits)).not.toMatch(/client-secret|refresh-a|access-token/);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );

  it.effect("does not make network requests for API keys or missing sign-ins", () =>
    Effect.gen(function* () {
      for (const options of [{ authMethod: "gemini-api-key" as const }, { missingToken: true }]) {
        const { probe, requests } = yield* fixture(options);
        expect((yield* probe).unavailable?.reason).toBe("unsupported");
        expect(requests).toEqual([]);
      }
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer)),
  );
});
