import { OktaAuth } from "https://cdn.jsdelivr.net/npm/@okta/okta-auth-js@7.8.1/+esm";

const CONFIG = {
  oktaIssuer: "https://integrator-1.okta.com/oauth2/default", //replace with okta id
  oktaClientId: "1", //replace with okta client id
  redirectUri: `${window.location.origin}/callback`, //switch to orginin if needed
  apiBaseUrl: "https://j6fv5stxuc.execute-api.us-east-1.amazonaws.com",
};


const oktaAuth = new OktaAuth({
  issuer: CONFIG.oktaIssuer,
  clientId: CONFIG.oktaClientId,
  redirectUri: CONFIG.redirectUri,
  scopes: ["openid", "profile", "email", "groups"],
  pkce: true,
});

const el = (id) => document.getElementById(id);

const ui = {
  status: el("status"),
  user: el("user"),
  groups: el("groups"),
  docId: el("docId"),
  tokenDebug: el("tokenDebug"),
  requestedGroup: el("requestedGroup"),
  reason: el("reason"),
  response: el("response"),
  btnLogin: el("btnLogin"),
  btnLogout: el("btnLogout"),
  btnRequest: el("btnRequest"),
  btnCopyExports: el("btnCopyExports"),
  btnClear: el("btnClear"),
  demoDept: el("demoDept"),
demoScope: el("demoScope"),
demoRequestedGroup: el("demoRequestedGroup"),
demoDocId: el("demoDocId"),
demoApproval: el("demoApproval"),
demoMaterial: el("demoMaterial"),
btnDemoEvaluate: el("btnDemoEvaluate"),
demoResult: el("demoResult"),

};

const ADMIN_GROUP = "JIT-AWS-Prod-Admin";

const ALLOWED_REQUESTED_GROUPS = new Set([
  "JIT-AWS-Prod-ReadOnly",
  "JIT-AWS-Prod-Admin",
]);

function normalizeGroups(raw) {
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [raw];
}

function canRequestGroup(jwtGroups, requestedGroup) {
  if (!ALLOWED_REQUESTED_GROUPS.has(requestedGroup)) return false;

  if (jwtGroups.includes(requestedGroup)) return true;

  if (jwtGroups.includes(ADMIN_GROUP)) return true;

  return false;
}


let lastCreds = null;

function setStatus(text) {
  ui.status.textContent = text;
}

function setResponse(objOrText) {
  if (typeof objOrText === "string") ui.response.textContent = objOrText;
  else ui.response.textContent = JSON.stringify(objOrText, null, 2);
}

function renderGroups(groups = []) {
  ui.groups.innerHTML = "";
  if (!groups.length) {
    ui.groups.innerHTML = `<span class="muted">—</span>`;
    return;
  }
  groups.forEach((g) => {
    const d = document.createElement("span");
    d.className = "chip";
    d.textContent = g;
    ui.groups.appendChild(d);
  });
}

function buildExports(creds) {
  return [
    `export AWS_ACCESS_KEY_ID="${creds.AccessKeyId}"`,
    `export AWS_SECRET_ACCESS_KEY="${creds.SecretAccessKey}"`,
    `export AWS_SESSION_TOKEN="${creds.SessionToken}"`,
    `export AWS_REGION="us-east-1"`,
  ].join("\n");
}

async function refreshUi(_authState) {
  const idTok = await oktaAuth.tokenManager.get("idToken");
  const atTok = await oktaAuth.tokenManager.get("accessToken");

  const isAuth = !!(idTok || atTok);

  ui.btnLogin.disabled = isAuth;
  ui.btnLogout.disabled = !isAuth;
  ui.btnRequest.disabled = !isAuth;

  if (!isAuth) {
    setStatus("Signed out");
    ui.user.textContent = "—";
    renderGroups([]);
    ui.tokenDebug.textContent = "";
    return;
  }

  setStatus("Signed in");

  const claims = idTok?.claims || atTok?.claims || {};
  ui.user.textContent =
    claims.email || claims.preferred_username || claims.sub || "—";

  let groups = atTok?.claims?.groups ?? idTok?.claims?.groups ?? [];
  if (typeof groups === "string") groups = [groups];
  if (!Array.isArray(groups)) groups = [];

  renderGroups(groups);

  ui.tokenDebug.textContent = JSON.stringify(
    {
      hasIdToken: !!idTok,
      hasAccessToken: !!atTok,
      aud: atTok?.claims?.aud,
      iss: (idTok?.claims?.iss || atTok?.claims?.iss),
      sub: claims.sub,
      exp: atTok?.claims?.exp,
      groups,
    },
    null,
    2
  );
}

async function handleLogin() {
  await oktaAuth.signInWithRedirect();
}


async function handleLogout() {
  lastCreds = null;
  ui.btnCopyExports.disabled = true;
  setResponse("Signed out.");

  oktaAuth.stop();
  await oktaAuth.tokenManager.clear();

  await oktaAuth.signOut({ postLogoutRedirectUri: window.location.origin });

  window.location.replace(window.location.origin + "/");
}


async function handleCallbackIfNeeded() {
  if (!oktaAuth.isLoginRedirect()) return;

  try {
    await oktaAuth.handleRedirect();
  } finally {
    window.history.replaceState({}, document.title, "/jit-broker/index-broker.html");
  }
}

async function requestJit() {
  lastCreds = null;
  ui.btnCopyExports.disabled = true;

  const reason = ui.reason.value.trim();
  const requested_group = ui.requestedGroup.value;
  const doc_id = ui.docId.value.trim();

  if (!reason) {
    setResponse("Reason is required.");
    return;
  }

  if (requested_group === "JIT-AWS-Prod-Admin" && !doc_id) {
    setResponse("Document/Ticket is required for Prod Admin.");
    return;
  }

  const token = await oktaAuth.tokenManager.get("accessToken");
  const accessToken = token?.accessToken;
  if (!accessToken) {
    setResponse("No access token found. Please sign in again.");
    return;
  }

  const jwtGroups = normalizeGroups(token?.claims?.groups);
  if (!canRequestGroup(jwtGroups, requested_group)) {
    setResponse({
      httpStatus: 403,
      error: "Not allowed to request this group",
      requested_group,
      jwt_groups: jwtGroups,
      note: `Allowed if member of requested group OR member of ${ADMIN_GROUP}.`,
    });
    return;
  }

  setResponse("Requesting…");

const res = await fetch(`${CONFIG.apiBaseUrl}/assume`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ reason, requested_group, doc_id }),
});


  const data = await res.json().catch(() => ({}));
  setResponse({ httpStatus: res.status, ...data });

  if (res.ok && data.credentials) {
    lastCreds = data.credentials;
    ui.btnCopyExports.disabled = false;
  }
}


async function copyExports() {
  if (!lastCreds) return;
  await navigator.clipboard.writeText(buildExports(lastCreds));
  ui.btnCopyExports.textContent = "Copied!";
  setTimeout(() => (ui.btnCopyExports.textContent = "Copy AWS exports"), 900);
}

ui.btnLogin.addEventListener("click", handleLogin);
ui.btnLogout.addEventListener("click", handleLogout);
ui.btnRequest.addEventListener("click", requestJit);
ui.btnCopyExports.addEventListener("click", copyExports);
ui.btnClear.addEventListener("click", () => setResponse("Cleared."));
ui.btnDemoEvaluate.addEventListener("click", () => {
  const input = {
    dept: ui.demoDept.value,
    scope: ui.demoScope.value,
    requestedGroup: ui.demoRequestedGroup.value,
    docId: ui.demoDocId.value.trim(),
    approvalStatus: ui.demoApproval.value,
    materialType: ui.demoMaterial.value,
  };

  const result = demoEvaluateAccess(input);
  renderDemoResult(result);
});


await handleCallbackIfNeeded();

oktaAuth.authStateManager.subscribe(refreshUi);
oktaAuth.start();

await refreshUi();

const DEMO_POLICY = {
  deptGroupPolicy: {
    SRE: ["JIT-AWS-Prod-ReadOnly", "JIT-AWS-Prod-Admin"],
    Finance: ["JIT-AWS-Prod-ReadOnly"],
    Intern: [],
    Unknown: ["JIT-AWS-Prod-ReadOnly"], // optional safety
  },
  docRequirements: {
    "JIT-AWS-Prod-Admin": {
      required: true,
      patterns: [/^CHG\d{6}$/, /^INC\d{6}$/],
    },
  },
};

function demoEvaluateAccess(input) {
  const {
    dept,
    scope, 
    requestedGroup,
    docId,
    approvalStatus,
    materialType,
  } = input;

  const reasons = [];
  const fixes = [];

  const isGlobal = scope === "global";
  const isAdminOrAbove = scope === "admin" || scope === "global";

  if (materialType === "non_confidential") {
    reasons.push("Non-confidential material: always allowed.");
  } else {
    if (!isAdminOrAbove) {
      reasons.push("Confidential material requires Admin or Global.");
      fixes.push("Select scope = Admin/Global (or in real flow: add user to Admin/Global group).");
      return { allowed: false, reasons, fixes };
    }
    reasons.push("Confidential material: allowed because scope is Admin/Global.");
  }

  if (!isGlobal) {
    const allowedByDept = (DEMO_POLICY.deptGroupPolicy[dept] || []).includes(requestedGroup);
    if (!allowedByDept) {
      reasons.push(`Blocked by department policy: ${dept} cannot request ${requestedGroup}.`);
      fixes.push("Change department or request a role allowed for this department.");
      return { allowed: false, reasons, fixes };
    }
    reasons.push(`Department policy allows ${requestedGroup} for ${dept}.`);
  } else {
    reasons.push("Global scope: bypasses department policy.");
  }

  const rule = DEMO_POLICY.docRequirements[requestedGroup];
  if (rule?.required) {
    if (!docId) {
      reasons.push(`Document required for ${requestedGroup}.`);
      fixes.push("Provide CHG/INC (e.g. CHG123456).");
      return { allowed: false, reasons, fixes };
    }
    const matches = rule.patterns.some((r) => r.test(docId));
    if (!matches) {
      reasons.push(`Document ID format invalid: ${docId}`);
      fixes.push("Use CHG###### or INC######.");
      return { allowed: false, reasons, fixes };
    }
    reasons.push(`Document format OK: ${docId}`);

    if (approvalStatus !== "approved") {
      reasons.push(`Document not approved: ${docId}`);
      fixes.push("Mark as Approved (or in real flow: add APPROVED record in DynamoDB).");
      return { allowed: false, reasons, fixes };
    }
    reasons.push(`Document approved: ${docId}`);
  } else {
    reasons.push(`No document required for ${requestedGroup}.`);
  }

  if (requestedGroup === "JIT-AWS-Prod-Admin" && !isAdminOrAbove) {
    reasons.push("Requested Admin role requires Admin/Global scope.");
    fixes.push("Select scope = Admin/Global.");
    return { allowed: false, reasons, fixes };
  }

  reasons.push("All checks passed.");
  return { allowed: true, reasons, fixes };
}

function renderDemoResult(result) {
  ui.demoResult.textContent = JSON.stringify(
    {
      allowed: result.allowed,
      reasons: result.reasons,
      recommended_fixes: result.fixes,
    },
    null,
    2
  );
}

