import os
import json
import boto3

sts = boto3.client("sts")

ROLE_MAP_RAW = os.environ.get("ROLE_MAP", "{}")
DEFAULT_ROLE_GROUP = (os.environ.get("DEFAULT_ROLE_GROUP") or "").strip()
DEFAULT_DURATION = int(os.environ.get("DEFAULT_DURATION") or "3600")

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

def _load_role_map():
    try:
        m = json.loads(ROLE_MAP_RAW)
        if not isinstance(m, dict):
            raise ValueError("ROLE_MAP must be a JSON object")
        return {str(k).strip(): str(v).strip() for k, v in m.items()}
    except Exception as e:
        raise ValueError(f"ROLE_MAP env var invalid JSON object: {e}")

ROLE_MAP = None
ROLE_MAP_ERR = None
try:
    ROLE_MAP = _load_role_map()
except Exception as e:
    ROLE_MAP_ERR = str(e)

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
    Handles formats:
      - ["A","B"]
      - "A"
      - "A,B"
      - '["A","B"]'  (stringified JSON list)
      - "[A,B]" or "[A]" (your screenshot format; not valid JSON)
      - '["[A]"]' etc (nested weirdness)
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

def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method")
    if method == "OPTIONS":
        return _resp(200, {"ok": True})

    if ROLE_MAP_ERR:
        return _resp(500, {"error": ROLE_MAP_ERR})

    try:
        body = json.loads(event.get("body") or "{}")
        if not isinstance(body, dict):
            return _resp(400, {"error": "Body must be a JSON object"})
    except Exception:
        return _resp(400, {"error": "Invalid JSON body"})

    reason = (body.get("reason") or "").strip()
    requested_group = (body.get("requested_group") or "").strip()

    if not reason:
        return _resp(400, {"error": "Missing required field: reason"})

    if not requested_group:
        requested_group = DEFAULT_ROLE_GROUP

    if not requested_group:
        return _resp(400, {"error": "Missing required field: requested_group (and DEFAULT_ROLE_GROUP not set)"})

    target_role_arn = ROLE_MAP.get(requested_group)
    if not target_role_arn:
        return _resp(403, {"error": "requested_group not allowed by ROLE_MAP", "requested_group": requested_group})

    duration = body.get("duration_seconds")
    if duration is None:
        duration = DEFAULT_DURATION
    try:
        duration = int(duration)
    except Exception:
        return _resp(400, {"error": "duration_seconds must be an integer"})
    if duration < 900:
        duration = 900
    if duration > 3600:
        duration = 3600

    claims = _claims(event)
    jwt_groups = _get_groups_from_claims(claims)

    if requested_group not in jwt_groups:
        return _resp(403, {
            "error": "User not in requested_group",
            "requested_group": requested_group,
            "jwt_groups": jwt_groups,
            "groups_claim_type": type(claims.get("groups")).__name__,
        })

    okta_user = (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("sub")
        or "unknown"
    )
    okta_sub = claims.get("uid") or claims.get("sub") or "unknown"

    try:
        out = sts.assume_role(
            RoleArn=target_role_arn,
            RoleSessionName=f"okta_{str(okta_sub)[:24]}",
            DurationSeconds=duration,
            Tags=[
                {"Key": "okta_user", "Value": str(okta_user)[:256]},
                {"Key": "okta_sub", "Value": str(okta_sub)[:256]},
                {"Key": "reason", "Value": reason[:256]},
                {"Key": "requested_group", "Value": requested_group[:256]},
            ],
        )
    except Exception as e:
        return _resp(403, {"error": "assume_role_failed", "detail": str(e), "target_role": target_role_arn})

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
