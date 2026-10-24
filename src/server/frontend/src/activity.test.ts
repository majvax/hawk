import { describe, expect, test } from "bun:test";

import {
  type ActivityEvent,
  activityQuery,
  describeDetails,
  eventCategory,
  eventLabel,
  formatBytes,
  formatDuration,
  kindsFor,
} from "./activity.js";

const event = (overrides: Partial<ActivityEvent>): ActivityEvent => ({
  id: 1,
  at: 0,
  kind: "view_ended",
  userId: 2,
  userEmail: "bob@example.com",
  subjectId: null,
  subjectEmail: null,
  machineId: "m1",
  machineName: "desk",
  role: "control",
  ip: "192.0.2.1",
  userAgent: null,
  details: {},
  ...overrides,
});

describe("activity", () => {
  test("labels and categories", () => {
    expect(eventLabel("shell_used")).toBe("Used a shell");
    expect(eventLabel("something_new")).toBe("something new");
    expect(eventCategory("power")).toBe("actions");
    expect(eventCategory("something_new")).toBe("all");
  });

  test("categories ask for their kinds, everything for none", () => {
    expect(kindsFor("all")).toEqual([]);
    expect(kindsFor("sessions")).toEqual(["view_started", "view_ended", "view_rejected", "view_elevated"]);
    expect(kindsFor("actions")).toContain("ctrl_alt_del");
    expect(kindsFor("account")).not.toContain("power");
  });

  test("the query carries only what's set", () => {
    expect(activityQuery({})).toBe("");
    expect(activityQuery({ machine: "a b", before: 40, limit: 50 })).toBe("?machine=a+b&before=40&limit=50");
    expect(activityQuery({ category: "machines", since: 10.7, user: 3 })).toBe(
      "?user=3&kind=machine_enrolled%2Cmachine_renamed%2Cmachine_removed%2Cshare_granted%2Cshare_revoked&since=10",
    );
  });

  test("bytes and durations", () => {
    expect(formatBytes(340)).toBe("340 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(50 * 1024 * 1024)).toBe("50 MB");
    expect(formatDuration(8)).toBe("8s");
    expect(formatDuration(192)).toBe("3m 12s");
    expect(formatDuration(3840)).toBe("1h 04m");
  });

  test("details in a few words", () => {
    expect(describeDetails(event({ details: { seconds: 192, filesDown: 2048 } }))).toBe("3m 12s · files ↓ 2.0 KB");
    expect(
      describeDetails(
        event({ kind: "share_granted", userId: 1, subjectId: 2, subjectEmail: "bob@example.com", role: "view", details: { singleView: true } }),
      ),
    ).toBe("bob@example.com · as view · one viewing");
    expect(describeDetails(event({ kind: "sign_in_failed", role: null, details: { reason: "wrong password" } }))).toBe(
      "wrong password",
    );
    expect(describeDetails(event({ kind: "machine_renamed", role: null, details: { name: "Study" } }))).toBe('to "Study"');
  });
});
