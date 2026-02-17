#!/bin/bash
# Clean workdir while preserving AI cost data
# Usage: sudo ./setup/clean_workdir.sh

WORKDIR="$(dirname "$0")/../workdir"
WORKDIR="$(cd "$WORKDIR" && pwd)"

if [ ! -d "$WORKDIR" ]; then
    echo "workdir not found: $WORKDIR"
    exit 1
fi

# AI cost files to preserve (NEVER delete these)
COST_FILES=(
    "ai-cost.json"
    "ai-emb-cost.json"
    "specgen_cost.json"
)

# Backup cost files
TMPDIR=$(mktemp -d)
for f in "${COST_FILES[@]}"; do
    if [ -f "$WORKDIR/$f" ]; then
        cp "$WORKDIR/$f" "$TMPDIR/$f"
        echo "Preserved: $f"
    fi
done

# Clean everything
rm -rf "$WORKDIR"/*

# Restore cost files
for f in "${COST_FILES[@]}"; do
    if [ -f "$TMPDIR/$f" ]; then
        cp "$TMPDIR/$f" "$WORKDIR/$f"
    fi
done
rm -rf "$TMPDIR"

# Clean MOCK BiGRU model state (forces retrain from new corpus)
MOCK_DIR="$(dirname "$0")/../tools/mock_model"
for f in model.pt vocab.pt training_data.jsonl; do
    if [ -f "$MOCK_DIR/$f" ]; then
        rm -f "$MOCK_DIR/$f"
        echo "Removed: mock_model/$f"
    fi
done

echo "Workdir cleaned. Cost data preserved. MOCK model reset (will retrain from new corpus)."
