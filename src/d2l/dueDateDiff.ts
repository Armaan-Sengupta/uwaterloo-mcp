/**
 * Due-date snapshot and change detection for LEARN assignments and quizzes.
 */

export interface DueDateSnapshotItem {
  courseId: number;
  courseName: string;
  kind: "assignment" | "quiz";
  id: number;
  name: string;
  dueDate: string;
}

export interface DueDateSnapshot {
  capturedAt: string;
  items: DueDateSnapshotItem[];
}

export interface DueDateChange {
  changeType: "changed" | "added" | "removed";
  courseId: number;
  courseName: string;
  kind: "assignment" | "quiz";
  id: number;
  name: string;
  previousDueDate: string | null;
  newDueDate: string | null;
}

export interface DueDateDiffResult {
  initialized: boolean;
  previousCapturedAt: string | null;
  currentCapturedAt: string;
  trackedCount: number;
  changes: DueDateChange[];
}

function itemKey(item: Pick<DueDateSnapshotItem, "courseId" | "kind" | "id">): string {
  return `${item.courseId}:${item.kind}:${item.id}`;
}

function datesEqual(a: string, b: string): boolean {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (!Number.isNaN(ta) && !Number.isNaN(tb)) return ta === tb;
  return a.trim() === b.trim();
}

const CHANGE_ORDER: Record<DueDateChange["changeType"], number> = {
  changed: 0,
  added: 1,
  removed: 2,
};

/**
 * Compares `current` due dates against `previous` snapshot.
 * If `previous` is null, marks `initialized: true` with an empty change list so the first run
 * establishes a baseline instead of treating every existing assignment as newly added.
 */
export function diffDueDateSnapshots(
  previous: DueDateSnapshot | null | undefined,
  current: readonly DueDateSnapshotItem[],
  now: Date = new Date(),
): { result: DueDateDiffResult; nextSnapshot: DueDateSnapshot } {
  const currentCapturedAt = now.toISOString();
  const nextSnapshot: DueDateSnapshot = {
    capturedAt: currentCapturedAt,
    items: [...current].sort((a, b) => itemKey(a).localeCompare(itemKey(b))),
  };

  if (!previous) {
    return {
      result: {
        initialized: true,
        previousCapturedAt: null,
        currentCapturedAt,
        trackedCount: nextSnapshot.items.length,
        changes: [],
      },
      nextSnapshot,
    };
  }

  const prevMap = new Map<string, DueDateSnapshotItem>();
  for (const item of previous.items) {
    prevMap.set(itemKey(item), item);
  }

  const currMap = new Map<string, DueDateSnapshotItem>();
  for (const item of nextSnapshot.items) {
    currMap.set(itemKey(item), item);
  }

  const changes: DueDateChange[] = [];

  for (const [key, curr] of currMap) {
    const prev = prevMap.get(key);
    if (!prev) {
      changes.push({
        changeType: "added",
        courseId: curr.courseId,
        courseName: curr.courseName,
        kind: curr.kind,
        id: curr.id,
        name: curr.name,
        previousDueDate: null,
        newDueDate: curr.dueDate,
      });
    } else if (!datesEqual(prev.dueDate, curr.dueDate)) {
      changes.push({
        changeType: "changed",
        courseId: curr.courseId,
        courseName: curr.courseName,
        kind: curr.kind,
        id: curr.id,
        name: curr.name,
        previousDueDate: prev.dueDate,
        newDueDate: curr.dueDate,
      });
    }
  }

  for (const [key, prev] of prevMap) {
    if (!currMap.has(key)) {
      changes.push({
        changeType: "removed",
        courseId: prev.courseId,
        courseName: prev.courseName,
        kind: prev.kind,
        id: prev.id,
        name: prev.name,
        previousDueDate: prev.dueDate,
        newDueDate: null,
      });
    }
  }

  changes.sort(
    (a, b) =>
      CHANGE_ORDER[a.changeType] - CHANGE_ORDER[b.changeType] ||
      a.courseName.localeCompare(b.courseName) ||
      a.name.localeCompare(b.name),
  );

  return {
    result: {
      initialized: false,
      previousCapturedAt: previous.capturedAt,
      currentCapturedAt,
      trackedCount: nextSnapshot.items.length,
      changes,
    },
    nextSnapshot,
  };
}
