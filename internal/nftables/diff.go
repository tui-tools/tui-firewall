package nftables

import (
	"fmt"
	"strings"
)

// UnifiedDiff renders the change between two texts as a unified diff: the
// familiar ---/+++ header and one hunk per run of changes, three lines of
// context around each. It is what the Save preview shows — the file as it is
// against the file the confirm would install — so "what does saving change"
// is answered before anything is written.
//
// It is a plain longest-common-subsequence diff over lines. The files it
// compares are one table's listing; quadratic is fine at that size.
func UnifiedDiff(oldText, newText, oldLabel, newLabel string) string {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)
	ops := diffOps(oldLines, newLines)
	hunks := groupHunks(ops, 3)
	if len(hunks) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", oldLabel, newLabel)
	for _, hunk := range hunks {
		writeHunk(&b, hunk, oldLines, newLines)
	}
	return strings.TrimRight(b.String(), "\n")
}

// diffOp is one line of the diff: kept, deleted or added.
type diffOp struct {
	// kind is ' ', '-' or '+'.
	kind byte
	// oldIndex and newIndex are the 0-based line positions; -1 where the op
	// has no line on that side.
	oldIndex, newIndex int
}

// splitLines cuts a text into lines without a trailing phantom.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(text, "\n"), "\n")
}

// diffOps walks the LCS table into the op list.
func diffOps(oldLines, newLines []string) []diffOp {
	n, m := len(oldLines), len(newLines)
	// lcs[i][j] is the length of the longest common subsequence of
	// oldLines[i:] and newLines[j:].
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case oldLines[i] == newLines[j]:
			ops = append(ops, diffOp{' ', i, j})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{'-', i, -1})
			i++
		default:
			ops = append(ops, diffOp{'+', -1, j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{'-', i, -1})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{'+', -1, j})
	}
	return ops
}

// groupHunks slices the op list into hunks: runs of changes with up to
// context kept lines around each, merged when their contexts touch.
func groupHunks(ops []diffOp, context int) [][]diffOp {
	var hunks [][]diffOp
	start := -1 // index into ops where the current hunk began
	lastChange := -1
	for i, op := range ops {
		if op.kind == ' ' {
			if start >= 0 && i-lastChange > context*2 {
				hunks = append(hunks, ops[start:lastChange+context+1])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = max(i-context, 0)
		}
		lastChange = i
	}
	if start >= 0 {
		end := min(lastChange+context+1, len(ops))
		hunks = append(hunks, ops[start:end])
	}
	return hunks
}

// writeHunk renders one hunk with its @@ header.
func writeHunk(b *strings.Builder, hunk []diffOp, oldLines, newLines []string) {
	oldStart, newStart := 0, 0
	oldCount, newCount := 0, 0
	for i, op := range hunk {
		if op.oldIndex >= 0 {
			if oldCount == 0 {
				oldStart = op.oldIndex + 1
			}
			oldCount++
		}
		if op.newIndex >= 0 {
			if newCount == 0 {
				newStart = op.newIndex + 1
			}
			newCount++
		}
		_ = i
	}
	// A side with no lines at all points just before where the change lands,
	// the way diff(1) spells an empty range.
	fmt.Fprintf(b, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
	for _, op := range hunk {
		switch op.kind {
		case ' ':
			b.WriteString(" " + oldLines[op.oldIndex] + "\n")
		case '-':
			b.WriteString("-" + oldLines[op.oldIndex] + "\n")
		case '+':
			b.WriteString("+" + newLines[op.newIndex] + "\n")
		}
	}
}
