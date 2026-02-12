import os
import json
import time
import re
import boto3

ddb = boto3.resource("dynamodb")
sts = boto3.client("sts")

GLOBAL_GROUP = (os.environ.get("GLOBAL_GROUP", "JIT-AWS-Global") or "").strip()
ADMIN_GROUP = (os.environ.get("ADMIN_GROUP", "JIT-AWS-Prod-Admin") or "").strip()

DEPT_CLAIM = (os.environ.get("DEPT_CLAIM", "department") or "").strip()

DEFAULT_ROLE_GROUP = (os.environ.get("DEFAULT_ROLE_GROUP") or "").strip()
DEFAULT_DURATION = int(os.environ.get("DEFAULT_DURATION") or "3600")

ROLE_MAP_RAW = os.environ.get("ROLE_MAP", "{}")
DEPT_GROUP_POLICY_RAW = os.environ.get("DEPT_GROUP_POLICY", "{}")
DOC_REQUIREMENTS_RAW = os.environ.get("DOC_REQUIREMENTS", "{}")

APPROVALS_TABLE = (os.environ.get("APPROVALS_TABLE") or "").strip()
APPROVALS = ddb.Table(APPROVALS_TABLE) if APPROVALS_TABLE else None

ADMIN_CAN_REQUEST = {
    "JIT-AWS-Prod-ReadOnly",
    "JIT-AWS-Prod-Admin",
}

ROLE_MAP = None
DEPT_GROUP_POLICY = None
DOC_REQUIREMENTS = None
BOOT_ERR = None


def _load_json_obj(raw: str, name: str):
    obj = json.loads(raw or "{}")
    if not isinstance(obj, dict):
        raise ValueError(f"{name} must be a JSON object")
    return obj


try:
    ROLE_MAP = _load_json_obj(ROLE_MAP_RAW, "ROLE_MAP")
    # Normalize keys/values
    ROLE_MAP = {str(k).strip(): str(v).strip() for k, v in ROLE_MAP.items()}

    DEPT_GROUP_POLICY = _load_json_obj(DEPT_GROUP_POLICY_RAW, "DEPT_GROUP_POLICY")
    DOC_REQUIREMENTS = _load_json_obj(DOC_REQUIREMENTS_RAW, "DOC_REQUIREMENTS")
except Exception as e:
    BOOT_ERR = str(e)

def _resp(code: int, body: dict):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(body),
    }


def _claims(event: dict) -> dict:
    return (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
        .get("claims", {})
        or {}
    )


def _normalize_groups(raw):
    """
    Handles:
      - ["A","B"]
      - "A"
      - "A,B"
      - '["A","B"]'
      - "[A,B]" / "[A]"
    Returns: list[str]
    """
    if raw is None:
        return []

    if isinstance(raw, list):
        out = []
        for x in raw:
            out.extend(_normalize_groups(x))
        return [g for g in out if g]

    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []

        if s.startswith("[") and s.endswith("]"):
            # Try JSON first
            try:
                val = json.loads(s)
                return _normalize_groups(val)
            except Exception:
                inner = s[1:-1].strip()
                if not inner:
                    return []
                parts = [p.strip().strip('"').strip("'") for p in inner.split(",")]
                return [p for p in parts if p]

        parts = [p.strip().strip('"').strip("'") for p in s.split(",")]
        return [p for p in parts if p]

    return []


def _get_groups_from_claims(claims: dict):
    raw = claims.get("groups") or claims.get("group") or claims.get("Groups")
    return _normalize_groups(raw)


def _get_department(claims: dict) -> str:
    v = claims.get(DEPT_CLAIM) or claims.get("dept") or claims.get("Department") or ""
    return str(v).strip()


def _dept_allows(dept: str, requested_group: str) -> bool:
    allowed = DEPT_GROUP_POLICY.get(dept)
    if not isinstance(allowed, list):
        return False
    allowed_norm = {str(x).strip() for x in allowed}
    return requested_group in allowed_norm


def _doc_required_for(requested_group: str):
    rule = DOC_REQUIREMENTS.get(requested_group)
    return rule if isinstance(rule, dict) else None


def _doc_matches_patterns(doc_id: str, patterns: list) -> bool:
    if not patterns:
        return True
    for p in patterns:
        try:
            if re.match(p, doc_id):
                return True
        except Exception:
            continue
    return False


def _validate_doc_approval(doc_id: str, requested_group: str):
    if not APPROVALS:
        return False, "Approvals table not configured (APPROVALS_TABLE missing)"

    item = APPROVALS.get_item(Key={"docId": doc_id}).get("Item")
    if not item:
        return False, "Document not found or not approved yet"

    status = str(item.get("status") or "").upper()
    if status != "APPROVED":
        return False, f"Document status is {status or 'UNKNOWN'}"

    expires_at = item.get("expiresAt")
    if expires_at is not None:
        try:
            if int(expires_at) < int(time.time()):
                return False, "Document approval expired"
        except Exception:
            return False, "Invalid expiresAt on approval record"

    allowed_groups = item.get("allowedGroups") or []
    if isinstance(allowed_groups, str):
        allowed_groups = [allowed_groups]
    if isinstance(allowed_groups, list):
        allowed_groups = [str(x).strip() for x in allowed_groups]
    else:
        allowed_groups = []

    if allowed_groups and requested_group not in allowed_groups:
        return False, "Document not approved for this requested group"

    return True, "ok"


def lambda_handler(event, context):
    try:
        # Preflight
        method = event.get("requestContext", {}).get("http", {}).get("method")
        if method == "OPTIONS":
            return _resp(200, {"ok": True})

        if BOOT_ERR:
            return _resp(500, {"error": "config_error", "detail": BOOT_ERR})

        try:
            body = json.loads(event.get("body") or "{}")
            if not isinstance(body, dict):
                return _resp(400, {"error": "Body must be a JSON object"})
        except Exception:
            return _resp(400, {"error": "Invalid JSON body"})

        reason = (body.get("reason") or "").strip()
        requested_group = (body.get("requested_group") or "").strip()
        doc_id = (body.get("doc_id") or "").strip()

        if not reason:
            return _resp(400, {"error": "Missing required field: reason"})

        if not requested_group:
            requested_group = DEFAULT_ROLE_GROUP

        if not requested_group:
            return _resp(400, {"error": "Missing required field: requested_group (and DEFAULT_ROLE_GROUP not set)"})

        # Must be allowed by ROLE_MAP
        target_role_arn = ROLE_MAP.get(requested_group)
        if not target_role_arn:
            return _resp(403, {"error": "requested_group not allowed by ROLE_MAP", "requested_group": requested_group})

        duration = body.get("duration_seconds", DEFAULT_DURATION)
        try:
            duration = int(duration)
        except Exception:
            return _resp(400, {"error": "duration_seconds must be an integer"})

        duration = max(900, min(duration, 3600))

        claims = _claims(event)
        jwt_groups = _get_groups_from_claims(claims)

        is_admin = ADMIN_GROUP in jwt_groups
        is_global = GLOBAL_GROUP in jwt_groups

        allowed_by_membership = requested_group in jwt_groups
        allowed_by_admin = is_admin and requested_group in ADMIN_CAN_REQUEST

        if not (allowed_by_membership or allowed_by_admin or is_global):
            return _resp(403, {
                "error": "User not entitled for requested_group",
                "requested_group": requested_group,
                "jwt_groups": jwt_groups,
                "is_admin": is_admin,
                "admin_group": ADMIN_GROUP,
                "admin_can_request": sorted(list(ADMIN_CAN_REQUEST)),
                "is_global": is_global,
            })
        dept = _get_department(claims)
        if not is_global:
            if not _dept_allows(dept, requested_group):
                return _resp(403, {
                    "error": "Blocked by department policy",
                    "department": dept or "unknown",
                    "requested_group": requested_group
                })
        doc_rule = _doc_required_for(requested_group)
        if doc_rule and doc_rule.get("required") is True:
            patterns = doc_rule.get("patterns") or []

            if not doc_id:
                return _resp(403, {
                    "error": "Document required for this requested_group",
                    "requested_group": requested_group,
                    "required_patterns": patterns
                })

            if not _doc_matches_patterns(doc_id, patterns):
                return _resp(403, {
                    "error": "Document ID format invalid",
                    "doc_id": doc_id,
                    "required_patterns": patterns
                })

            ok, msg = _validate_doc_approval(doc_id, requested_group)
            if not ok:
                return _resp(403, {
                    "error": "Document not approved",
                    "doc_id": doc_id,
                    "detail": msg
                })

        okta_user = claims.get("email") or claims.get("preferred_username") or claims.get("sub") or "unknown"
        okta_sub = claims.get("uid") or claims.get("sub") or "unknown"

        try:
            tags = [
                {"Key": "okta_user", "Value": str(okta_user)[:256]},
                {"Key": "okta_sub", "Value": str(okta_sub)[:256]},
                {"Key": "department", "Value": (dept or "unknown")[:256]},
                {"Key": "is_global", "Value": ("true" if is_global else "false")},
                {"Key": "reason", "Value": reason[:256]},
                {"Key": "requested_group", "Value": requested_group[:256]},
                {"Key": "doc_id", "Value": (doc_id or "none")[:256]},
            ]

            out = sts.assume_role(
                RoleArn=target_role_arn,
                RoleSessionName=f"okta_{str(okta_sub)[:24]}",
                DurationSeconds=duration,
                Tags=tags,
            )
        except Exception as e:
            return _resp(403, {
                "error": "assume_role_failed",
                "detail": str(e),
                "target_role": target_role_arn
            })

        creds = out["Credentials"]
        exp = creds.get("Expiration")
        expires_at = exp.isoformat() if hasattr(exp, "isoformat") else str(exp)

        return _resp(200, {
            "assumed_role": out["AssumedRoleUser"]["Arn"],
            "expires_at": expires_at,
            "credentials": {
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken": creds["SessionToken"],
            }
        })

    except Exception as e:
        # prevents opaque 500s
        return _resp(500, {"error": "internal_error", "detail": str(e)})
