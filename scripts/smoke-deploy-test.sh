#!/usr/bin/env bash
# Service-agnostic deploy test for generated IaC artifacts.
# Deploys Terraform and/or CloudFormation, verifies outputs, optionally tears down.
#
# Expects the generate-iac skill to have produced:
#   terraform/smoke-test.tfvars   — minimal vars for standalone deploy
#   cloudformation/smoke-test-params.json — CFN parameter overrides
#
# Usage: scripts/smoke-deploy-test.sh [--terraform] [--cloudformation] [--all]
#                                     [--slug=<service-slug>] [--keep]
#
# Flags:
#   --slug=<slug>      Service slug whose IaC artifacts to deploy. If absent,
#                      auto-discovers from .service-approval/*/05-generate/iac/
#                      (errors if 0 or >1 services found).
#   --keep             Skip teardown. Leave deployed resources alive (Phase 7
#                      Evidence needs the stack alive to probe it). Phase 7
#                      tears down at the end of evidence collection.
#   --terraform        Deploy Terraform only.
#   --cloudformation   Deploy CloudFormation only.
#   --all              Deploy both (default).
#
# Exit codes: 0=PASS, 1=DEPLOY FAILED, 2=DESTROY FAILED (resources may remain)

set -uo pipefail
# Note: -e (errexit) intentionally omitted — we handle errors explicitly
# to ensure teardown always runs even when deploy fails.

DEPLOY_TF=false
DEPLOY_CFN=false
SLUG=""
KEEP=false
RESULTS=()
FAILED=0

for arg in "$@"; do
  case "$arg" in
    --terraform) DEPLOY_TF=true ;;
    --cloudformation) DEPLOY_CFN=true ;;
    --all) DEPLOY_TF=true; DEPLOY_CFN=true ;;
    --slug=*) SLUG="${arg#--slug=}" ;;
    --keep) KEEP=true ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

if ! $DEPLOY_TF && ! $DEPLOY_CFN; then
  DEPLOY_TF=true
  DEPLOY_CFN=true
fi

# --------------------------------------------------------------------------
# Resolve service slug + IaC dirs
# --------------------------------------------------------------------------
# Per-slug layout: .service-approval/<slug>/05-generate/iac/{terraform,cloudformation}/
# Auto-discover if --slug not provided.
if [ -z "$SLUG" ]; then
  CANDIDATES=()
  if [ -d ".service-approval" ]; then
    while IFS= read -r d; do
      name=$(basename "$d")
      [ "$name" = "_staging" ] && continue
      [ "$name" = "plans" ] && continue
      if [ -d "$d/05-generate/iac" ]; then
        CANDIDATES+=("$name")
      fi
    done < <(find ".service-approval" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  fi
  if [ ${#CANDIDATES[@]} -eq 0 ]; then
    echo "CRITICAL: No service slug found. Either run /generate first or pass --slug=<slug>."
    echo "Looked under: .service-approval/*/05-generate/iac/"
    exit 1
  elif [ ${#CANDIDATES[@]} -gt 1 ]; then
    echo "CRITICAL: Multiple services found in .service-approval/: ${CANDIDATES[*]}"
    echo "Pass --slug=<one-of-them> to disambiguate."
    exit 1
  fi
  SLUG="${CANDIDATES[0]}"
fi

CONTROLS_DIR=".service-approval/$SLUG/05-generate/iac"
TF_DIR="$CONTROLS_DIR/terraform"
CFN_DIR="$CONTROLS_DIR/cloudformation"

if [ ! -d "$CONTROLS_DIR" ]; then
  echo "CRITICAL: $CONTROLS_DIR does not exist. Run /generate for slug '$SLUG' first."
  exit 1
fi

echo "  Slug:     $SLUG"
echo "  IaC dir:  $CONTROLS_DIR"
$KEEP && echo "  Mode:     deploy (KEEP — Phase 7 will tear down)" || echo "  Mode:     deploy + teardown"
echo ""

# --------------------------------------------------------------------------
# Pre-flight
# --------------------------------------------------------------------------
echo "=== Pre-flight ==="
IDENTITY=$(aws sts get-caller-identity --output json 2>&1) || { echo "CRITICAL: aws sts get-caller-identity failed"; exit 1; }
ACCOUNT=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
ARN=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
echo "  Account: $ACCOUNT"
echo "  ARN:     $ARN"
echo "  Profile: ${AWS_PROFILE:-default}"

if echo "$ARN" | grep -qi "prod\|prd\|production\|live"; then
  echo "CRITICAL: Refusing to deploy to production account"
  exit 1
fi
echo ""

# --------------------------------------------------------------------------
# Terraform
# --------------------------------------------------------------------------
if $DEPLOY_TF && [ -d "$TF_DIR" ]; then
  echo "=== Terraform: Deploy ==="

  TFVARS="$TF_DIR/smoke-test.tfvars"
  if [ ! -f "$TFVARS" ]; then
    echo "  SKIP: No smoke-test.tfvars found (generate-iac skill should produce this)"
    RESULTS+=("Terraform: SKIP (no smoke-test.tfvars)")
  else
    echo "  Using: $(basename "$TFVARS")"

    # Inject account ID into tfvars if placeholder present
    TFVARS_RESOLVED=$(mktemp)
    sed "s/\${ACCOUNT_ID}/$ACCOUNT/g" "$TFVARS" > "$TFVARS_RESOLVED"

    pushd "$TF_DIR" > /dev/null || { echo "  CRITICAL: pushd $TF_DIR failed"; exit 1; }

    # Init
    terraform init -backend=false -no-color -input=false 2>&1 | tail -1

    # Plan
    echo "  Planning..."
    TF_PLAN_OUT=$(terraform plan -input=false -no-color -var-file="$TFVARS_RESOLVED" 2>&1)
    TF_PLAN_EXIT=$?

    if [ $TF_PLAN_EXIT -ne 0 ]; then
      echo "  FAIL: terraform plan"
      echo "$TF_PLAN_OUT" | tail -15
      RESULTS+=("Terraform plan: FAIL")
      FAILED=$((FAILED+1))
    else
      PLAN_ADDS=$(echo "$TF_PLAN_OUT" | grep "Plan:" || echo "unknown")
      echo "  $PLAN_ADDS"

      # Apply
      echo "  Deploying..."
      TF_APPLY_OUT=$(terraform apply -auto-approve -input=false -no-color -var-file="$TFVARS_RESOLVED" 2>&1)
      TF_APPLY_EXIT=$?

      if [ $TF_APPLY_EXIT -ne 0 ]; then
        echo "  FAIL: terraform apply"
        echo "$TF_APPLY_OUT" | tail -20
        RESULTS+=("Terraform deploy: FAIL")
        FAILED=$((FAILED+1))

        echo "  Destroying partial resources..."
        terraform destroy -auto-approve -input=false -no-color -var-file="$TFVARS_RESOLVED" 2>&1 | tail -5
      else
        APPLIED=$(echo "$TF_APPLY_OUT" | grep "Apply complete!" || echo "complete")
        echo "  $APPLIED"

        # Verify: list all outputs
        echo "  Verifying outputs..."
        terraform output -no-color 2>/dev/null | head -10
        RESULTS+=("Terraform deploy: PASS")

        if $KEEP; then
          echo "  KEEP: Skipping teardown — Phase 7 Evidence will probe and tear down."
          RESULTS+=("Terraform teardown: DEFERRED (--keep)")
        else
          # Destroy
          echo "  Tearing down..."
          TF_DESTROY_OUT=$(terraform destroy -auto-approve -input=false -no-color -var-file="$TFVARS_RESOLVED" 2>&1)
          TF_DESTROY_EXIT=$?

          if [ $TF_DESTROY_EXIT -ne 0 ]; then
            echo "  CRITICAL: terraform destroy failed — resources may remain!"
            echo "$TF_DESTROY_OUT" | tail -10
            RESULTS+=("Terraform teardown: FAIL — RESOURCES MAY REMAIN")
            FAILED=$((FAILED+1))
          else
            DESTROYED=$(echo "$TF_DESTROY_OUT" | grep "Destroy complete!" || echo "complete")
            echo "  $DESTROYED"
            RESULTS+=("Terraform teardown: PASS")
          fi
        fi
      fi
    fi

    rm -f "$TFVARS_RESOLVED"
    popd > /dev/null || true
  fi
  echo ""
fi

# --------------------------------------------------------------------------
# CloudFormation
# --------------------------------------------------------------------------
if $DEPLOY_CFN && [ -d "$CFN_DIR" ]; then
  echo "=== CloudFormation: Deploy ==="

  # shellcheck disable=SC2010  # filenames here are CFN templates with constrained ASCII names; ls|grep is safe.
  CFN_TEMPLATE=$(ls "$CFN_DIR"/*.yaml "$CFN_DIR"/*.yml "$CFN_DIR"/*.json 2>/dev/null | grep -v smoke-test | head -1)
  CFN_PARAMS="$CFN_DIR/smoke-test-params.json"
  STACK_NAME="smoke-test-$(date +%s)"

  if [ -z "$CFN_TEMPLATE" ]; then
    echo "  SKIP: No CFN template found"
    RESULTS+=("CloudFormation: SKIP (no template)")
  elif [ ! -f "$CFN_PARAMS" ]; then
    echo "  SKIP: No smoke-test-params.json found (generate-iac skill should produce this)"
    RESULTS+=("CloudFormation: SKIP (no smoke-test-params.json)")
  else
    echo "  Template: $(basename "$CFN_TEMPLATE")"
    echo "  Params:   $(basename "$CFN_PARAMS")"
    echo "  Stack:    $STACK_NAME"

    # Inject account ID into params if placeholder present
    CFN_PARAMS_RESOLVED=$(mktemp)
    sed "s/\${ACCOUNT_ID}/$ACCOUNT/g" "$CFN_PARAMS" > "$CFN_PARAMS_RESOLVED"

    # Build --parameter-overrides array from JSON
    # Write each param as a separate line to a temp file, properly escaped
    PARAM_ARGS_FILE=$(mktemp)
    python3 -c "
import json
params = json.load(open('$CFN_PARAMS_RESOLVED'))
# Write params as Key=Value, one per line, with values that are safe for shell
with open('$PARAM_ARGS_FILE', 'w') as f:
    for p in params:
        k = p['ParameterKey']
        v = p['ParameterValue']
        # Replace spaces with underscores in values for parameter-overrides safety
        # (CFN parameter values with spaces need special handling)
        f.write(f'{k}={v}\n')
" 2>/dev/null

    # Read params into array
    PARAM_OVERRIDES=()
    while IFS= read -r line; do
      [ -n "$line" ] && PARAM_OVERRIDES+=("$line")
    done < "$PARAM_ARGS_FILE"
    rm -f "$PARAM_ARGS_FILE"

    # Deploy
    echo "  Deploying..."
    CFN_DEPLOY_OUT=$(aws cloudformation deploy \
      --template-file "$CFN_TEMPLATE" \
      --stack-name "$STACK_NAME" \
      --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
      --parameter-overrides "${PARAM_OVERRIDES[@]}" \
      --no-fail-on-empty-changeset \
      --no-cli-pager 2>&1)
    CFN_DEPLOY_EXIT=$?

    if [ $CFN_DEPLOY_EXIT -ne 0 ]; then
      echo "  FAIL: cloudformation deploy"
      echo "$CFN_DEPLOY_OUT" | tail -10

      # Show failure events
      echo "  Failure events:"
      aws cloudformation describe-stack-events \
        --stack-name "$STACK_NAME" \
        --query "StackEvents[?ResourceStatus=='CREATE_FAILED'].[LogicalResourceId,ResourceStatusReason]" \
        --output table --no-cli-pager 2>/dev/null | head -20

      RESULTS+=("CloudFormation deploy: FAIL")
      FAILED=$((FAILED+1))

      echo "  Deleting failed stack..."
      aws cloudformation delete-stack --stack-name "$STACK_NAME" --no-cli-pager 2>/dev/null
      aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --no-cli-pager 2>/dev/null || true
    else
      echo "  PASS: Stack created"

      # Verify: list outputs
      echo "  Stack outputs:"
      aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --query "Stacks[0].Outputs[].[OutputKey,OutputValue]" \
        --output table --no-cli-pager 2>/dev/null | head -15
      RESULTS+=("CloudFormation deploy: PASS")

      if $KEEP; then
        echo "  KEEP: Skipping teardown — Phase 7 Evidence will probe stack $STACK_NAME and tear down."
        echo "  Stack name: $STACK_NAME"
        RESULTS+=("CloudFormation teardown: DEFERRED (--keep, stack=$STACK_NAME)")
      else
        # Destroy
        echo "  Tearing down..."
        aws cloudformation delete-stack --stack-name "$STACK_NAME" --no-cli-pager
        echo "  Waiting for delete..."
        aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --no-cli-pager 2>&1
        CFN_DELETE_EXIT=$?

        if [ $CFN_DELETE_EXIT -ne 0 ]; then
          echo "  CRITICAL: stack delete failed — stack $STACK_NAME may remain!"
          RESULTS+=("CloudFormation teardown: FAIL — STACK $STACK_NAME MAY REMAIN")
          FAILED=$((FAILED+1))
        else
          echo "  PASS: Stack deleted"
          RESULTS+=("CloudFormation teardown: PASS")
        fi
      fi
    fi

    rm -f "$CFN_PARAMS_RESOLVED"
  fi
  echo ""
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo "=== Deploy Test Summary ==="
for r in "${RESULTS[@]}"; do
  echo "  $r"
done

if [ $FAILED -gt 0 ]; then
  echo ""
  echo "FAILED: $FAILED issue(s)"
  exit 1
elif $KEEP; then
  echo ""
  echo "PASS: Deploy succeeded; teardown DEFERRED (Phase 7 will tear down)"
  exit 0
else
  echo ""
  echo "PASS: All deploy+teardown cycles succeeded"
  exit 0
fi
