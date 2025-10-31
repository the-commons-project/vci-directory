# VCI Directory Automated Audit Workflow

## Overview

The VCI directory uses a **two-stage automated workflow** to update the issuer snapshot while respecting branch protection rules.

## How It Works

### Stage 1: Nightly Audit & PR Creation
**Workflow:** `vci-directory-audit.yaml`
**Trigger:** Daily at 4:30 AM UTC (or manual via workflow_dispatch)

```
┌─────────────────────────────────────────────┐
│  1. Fetch all issuers from vci-issuers.json│
│  2. Download keys from each issuer          │
│  3. Validate keys (SHC compliance)          │
│  4. Check TLS configuration                 │
│  5. Fetch CRLs (if available)               │
│  6. Generate snapshot files                 │
│  7. Sign snapshot                           │
│  8. Create branch: audit/snapshot-YYYY-MM-DD│
│  9. Commit changes to branch                │
│ 10. Push branch & create Pull Request       │
└─────────────────────────────────────────────┘
```

**Outputs:**
- Creates a PR titled: `🤖 Automated VCI Directory Snapshot Update - YYYY-MM-DD`
- Labels: `automated`, `audit`
- PR body includes:
  - Total issuer count
  - Count of issuers with errors
  - Timestamp of audit
  - List of what changed

### Stage 2: Auto-merge After Checks Pass
**Workflow:** `auto-merge-audit-pr.yaml`
**Trigger:** When PR is created/updated OR when check suites complete

```
┌─────────────────────────────────────────────┐
│  1. Detect audit/* branch PR                │
│  2. Wait for required checks to pass:       │
│     - Test Scripts                          │
│     - Validate Issuers File                 │
│  3. Verify PR has 'automated' label         │
│  4. Add comment: "Merging in 30 seconds"    │
│  5. Wait 30 seconds (safety window)         │
│  6. Check if PR is still open               │
│  7. Squash merge to main                    │
└─────────────────────────────────────────────┘
```

**Safety Features:**
- ✅ Respects all branch protection rules
- ✅ 30-second window for manual intervention
- ✅ Won't merge if PR is closed
- ✅ Won't merge if checks fail
- ✅ Won't merge without 'automated' label

## Why This Approach?

### Previous Approach (Direct Push)
❌ **Problem:** Workflow tried to push directly to protected main branch
❌ **Result:** "Protected branch hook declined" error
❌ **Cause:** Branch protection requires status checks, but checks run in same workflow

### Current Approach (PR-Based)
✅ **Solution:** Create PR → checks run on PR → auto-merge after checks pass
✅ **Benefit:** Respects branch protection completely
✅ **Benefit:** Provides audit trail (PR history)
✅ **Benefit:** Allows manual review/intervention
✅ **Benefit:** Transparent for public repository

## Manual Intervention

### To Prevent a Merge

If you notice issues with an automated snapshot PR:

1. **Close the PR** - Auto-merge will abort
2. **Remove 'automated' label** - Auto-merge will skip it
3. **Do either within 30 seconds** of the "merging in 30s" comment

### To Force Merge

If auto-merge fails or you want to manually merge:

```bash
gh pr merge <PR_NUMBER> --squash --auto
```

### To Re-run Auto-merge

If auto-merge workflow had an error:

```bash
gh workflow run auto-merge-audit-pr.yaml -f pr_number=<PR_NUMBER>
```

## Monitoring

### Check Workflow Status

```bash
# List recent workflow runs
gh run list --workflow=vci-directory-audit.yaml

# View specific run
gh run view <run-id>

# List recent PRs
gh pr list --label automated
```

### Check Snapshot Updates

```bash
# View recent commits to main
git log --oneline --grep="snapshot update" -10

# Check latest snapshot timestamp
jq '.time' logs/vci_snapshot.json
```

## Troubleshooting

### Workflow Creates PR But Doesn't Merge

**Possible causes:**
1. Required checks haven't completed yet
2. Required checks failed
3. PR is missing 'automated' label
4. PR was closed during safety window

**Solution:**
- Check PR status: `gh pr view <PR_NUMBER> --json statusCheckRollup`
- Re-trigger checks if needed
- Manually merge if appropriate

### PR Shows Conflicts

**Cause:** Main branch was updated between PR creation and merge

**Solution:**
```bash
# Update the PR branch
git checkout audit/snapshot-YYYY-MM-DD
git pull origin main
git push origin audit/snapshot-YYYY-MM-DD
```

### Multiple PRs Accumulate

**Cause:** Previous PRs weren't merged (checks failed, etc.)

**Solution:**
```bash
# List open audit PRs
gh pr list --label automated --state open

# Close old PRs that are superseded
gh pr close <OLD_PR_NUMBER> --comment "Superseded by newer snapshot"
```

## Configuration

### Required Secrets

- `GITHUB_TOKEN` (automatically provided by GitHub Actions)
- `PRIVATE_SIG_KEY` - Private key for signing snapshots
- `PRIVATE_SIG_KEY_PWD` - Password for private key

### Branch Protection Settings

**Main branch must have:**
- ✅ Require pull request before merging
- ✅ Require status checks to pass:
  - `Test Scripts`
  - `Validate Issuers File`
- ⚠️ **Do NOT** require approvals (allow auto-merge)

### Labels

Ensure these labels exist in the repository:
- `automated` - Marks PRs created by automation
- `audit` - Categorizes as audit-related

## Maintenance

### Rotating Signing Key

1. Generate new private key
2. Update `PRIVATE_SIG_KEY` and `PRIVATE_SIG_KEY_PWD` secrets
3. Next audit run will use new key

### Adjusting Audit Schedule

Edit `vci-directory-audit.yaml`:
```yaml
on:
  schedule:
    - cron: '30 4 * * *'  # Change this cron expression
```

### Disabling Auto-merge Temporarily

Disable the `auto-merge-audit-pr.yaml` workflow:
1. Go to Actions tab in GitHub
2. Select "Auto-merge Audit PRs" workflow
3. Click "..." → "Disable workflow"

PRs will still be created but won't auto-merge.

## Architecture Decisions

### Why Not Direct Push with Bot Token?

**Considered:** Bot account with bypass permissions
**Rejected because:**
- Less transparent for public repository
- Bypasses important safety checks
- Harder to audit changes
- No review opportunity before merge

### Why 30-Second Safety Window?

**Purpose:** Allow human intervention if issues are spotted
**Trade-off:** Slight delay in merge (acceptable for daily updates)
**Alternative:** Could be reduced to 10-15 seconds if needed

### Why Squash Merge?

**Purpose:** Keep main branch history clean
**Result:** Each daily update = 1 commit on main
**Alternative:** Could use regular merge to preserve PR commits

## Support

For issues or questions:
- GitHub Issues: https://github.com/the-commons-project/vci-directory/issues
- Review workflow runs: https://github.com/the-commons-project/vci-directory/actions
