export type DiffKind = "same" | "added" | "removed";
export interface DiffLine { kind: DiffKind; text: string }

/** Line-based LCS diff. Inputs are small (a hooks JSON section), so O(n·m) is fine. */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split(/\r?\n/);
  const b = after.split(/\r?\n/);
  const n = a.length, m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      const row = lcs[i] as number[];
      row[j] = a[i] === b[j] ? ((lcs[i + 1] as number[])[j + 1] ?? 0) + 1 : Math.max((lcs[i + 1] as number[])[j] ?? 0, row[j + 1] ?? 0);
    }
  }
  const out: DiffLine[] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] ?? "" });
      i++;
      j++;
    } else if (((lcs[i + 1] as number[])[j] ?? 0) >= ((lcs[i] as number[])[j + 1] ?? 0)) {
      out.push({ kind: "removed", text: a[i] ?? "" });
      i++;
    } else {
      out.push({ kind: "added", text: b[j] ?? "" });
      j++;
    }
  }
  while (i < n) out.push({ kind: "removed", text: a[i++] ?? "" });
  while (j < m) out.push({ kind: "added", text: b[j++] ?? "" });
  return out;
}
