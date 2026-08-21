import crypto from "node:crypto";
import fs from "node:fs/promises";
import { JoseKey } from "/app/packages/oauth/jwk-jose/dist/index.js";
import { createDpopProof } from "/app/packages/space/dist/index.js";

const MESSAGE_COUNT = 99;
const SPACE_TYPE = "email.atmos.mailbox";
const MESSAGE = "email.atmos.message";
const STATE = "email.atmos.messageState";
const FOLDER = "email.atmos.folder";
const account = JSON.parse(await fs.readFile(required("ACCOUNT_FILE"), "utf8"));
const origin = required("PDS_ORIGIN");
const authorization = `Bearer ${account.accessJwt}`;
const space = `at://${account.did}/space/${SPACE_TYPE}/prepare-proof`;
const wrongSpace = `at://${account.did}/space/${SPACE_TYPE}/wrong-proof`;
const folderRkey = `folder-${sha256(Buffer.from("comail-folder-v1\0INBOX"))}`;

await ensureSpace(space, "prepare-proof");
await ensureSpace(wrongSpace, "wrong-proof");

await ensureFolder();
const atomicRollbackVerified = await proveAtomicRollback();

const expected = Array.from({ length: MESSAGE_COUNT }, (_, index) =>
  syntheticMessage(index),
);
const first = await prepare(expected);
const second = await prepare(expected);
if (
  first.captured !== MESSAGE_COUNT ||
  first.skipped !== 0 ||
  first.verified !== MESSAGE_COUNT ||
  second.captured !== 0 ||
  second.skipped !== MESSAGE_COUNT ||
  second.verified !== MESSAGE_COUNT
) {
  throw new Error("prepare counts did not prove a complete idempotent retry");
}

const inventory = await inventoryCounts();
if (inventory.messages !== MESSAGE_COUNT || inventory.states !== MESSAGE_COUNT) {
  throw new Error("complete destination inventory did not match the source");
}

const credentialChecks = await proveCredential(expected[0]);
const staleSwapAccepted = await proveMissingCAS(expected[0]);
if (!staleSwapAccepted) {
  throw new Error("alpha behavior changed: rerun the authority assessment before proceeding");
}

console.log(
  JSON.stringify({
    sourceMessages: MESSAGE_COUNT,
    first,
    second,
    inventory,
    atomicRollbackVerified,
    ...credentialChecks,
    staleSwapAccepted,
    schemaValidationAttempted: false,
    narrowOAuthGrantAttempted: false,
    compareAndSwap: false,
    authorityCertified: false,
    activationAttempted: false,
  }),
);

async function prepare(messages) {
  const report = { captured: 0, skipped: 0, verified: 0 };
  for (const message of messages) {
    const existing = await getRecord(MESSAGE, message.rkey, authorization, true);
    if (existing) {
      await verifyMessage(message, existing, authorization);
      report.skipped++;
      report.verified++;
      continue;
    }

    const blob = await uploadBlob(message.raw);
    await applyWrites([
      {
        $type: "com.atproto.space.applyWrites#create",
        collection: MESSAGE,
        rkey: message.rkey,
        value: {
          $type: MESSAGE,
          raw: blob,
          sha256: message.rawSHA256,
          size: message.raw.length,
          deliveryFingerprint: message.rkey,
          sourceKey: message.sourceKey,
          initialMailbox: "INBOX",
          deliveredAt: "2026-08-20T00:00:00Z",
          sourceMessageId: message.messageID,
        },
      },
      {
        $type: "com.atproto.space.applyWrites#create",
        collection: STATE,
        rkey: message.rkey,
        value: stateValue(message.rkey, 1),
      },
    ]);
    report.captured++;
    await verifyMessage(
      message,
      await getRecord(MESSAGE, message.rkey, authorization),
      authorization,
    );
    report.verified++;
  }
  return report;
}

async function ensureSpace(targetSpace, skey) {
  const response = await fetch(xrpcURL("com.atproto.simplespace.createSpace"), {
    method: "POST",
    redirect: "error",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify({
      type: SPACE_TYPE,
      skey,
      policy: { $type: "com.atproto.simplespace.defs#memberListPolicy" },
      appAccess: { $type: "com.atproto.simplespace.defs#open" },
    }),
  });
  const body = await response.json();
  if (response.ok) {
    if (body.uri !== targetSpace) throw new Error("createSpace returned the wrong URI");
    return;
  }
  if (body.error !== "SpaceAlreadyExists") {
    throw new Error(`createSpace failed with HTTP ${response.status}`);
  }
  const existing = await xrpcJSON(
    "com.atproto.simplespace.getSpace",
    "GET",
    { space: targetSpace },
  );
  if (
    existing.uri !== targetSpace ||
    existing.policy?.$type !== "com.atproto.simplespace.defs#memberListPolicy" ||
    existing.appAccess?.$type !== "com.atproto.simplespace.defs#open"
  ) {
    throw new Error("existing space policy did not match the exact proof target");
  }
}

async function ensureFolder() {
  const value = {
    $type: FOLDER,
    name: "INBOX",
    role: "inbox",
    uidValidity: 424242,
    revision: 1,
    updatedAt: "2026-08-20T00:00:00Z",
  };
  const existing = await getRecord(FOLDER, folderRkey, authorization, true);
  if (existing) {
    if (
      existing.value?.$type !== value.$type ||
      existing.value.name !== value.name ||
      existing.value.role !== value.role ||
      existing.value.uidValidity !== value.uidValidity ||
      existing.value.revision !== value.revision ||
      existing.value.updatedAt !== value.updatedAt
    ) {
      throw new Error("existing synthetic folder differs");
    }
    return;
  }
  await applyWrites([
    {
      $type: "com.atproto.space.applyWrites#create",
      collection: FOLDER,
      rkey: folderRkey,
      value,
    },
  ]);
}

async function verifyMessage(expectedMessage, stored, auth) {
  const value = stored.value;
  if (
    value?.$type !== MESSAGE ||
    value.deliveryFingerprint !== expectedMessage.rkey ||
    value.sourceKey !== expectedMessage.sourceKey ||
    value.sha256 !== expectedMessage.rawSHA256 ||
    value.size !== expectedMessage.raw.length ||
    value.raw?.mimeType !== "message/rfc822" ||
    value.raw?.size !== expectedMessage.raw.length ||
    typeof value.raw?.ref?.$link !== "string"
  ) {
    throw new Error("stored message metadata failed exact verification");
  }
  const state = await getRecord(STATE, expectedMessage.rkey, auth);
  if (
    state.value?.$type !== STATE ||
    state.value.message !== expectedMessage.rkey ||
    state.value.revision !== 1 ||
    state.value.mailboxIds?.length !== 1 ||
    state.value.mailboxIds[0] !== folderRkey
  ) {
    throw new Error("stored message state failed exact verification");
  }
  const blobURL = xrpcURL("com.atproto.space.getBlob", {
    space,
    repo: account.did,
    cid: value.raw.ref.$link,
  });
  const response = await fetch(blobURL, {
    redirect: "error",
    headers: { authorization: auth },
  });
  if (!response.ok) throw new Error(`getBlob failed with HTTP ${response.status}`);
  const raw = Buffer.from(await response.arrayBuffer());
  if (!raw.equals(expectedMessage.raw) || sha256(raw) !== expectedMessage.rawSHA256) {
    throw new Error("canonical RFC 5322 readback was not byte-exact");
  }
}

async function inventoryCounts() {
  const messages = await listAll(MESSAGE, authorization);
  const states = await listAll(STATE, authorization);
  return { messages: messages.length, states: states.length };
}

async function listAll(collection, auth) {
  const records = [];
  let cursor;
  do {
    const page = await xrpcJSON(
      "com.atproto.space.listRecords",
      "GET",
      { space, repo: account.did, collection, limit: "1000", cursor },
      undefined,
      auth,
    );
    records.push(...page.records);
    cursor = page.cursor;
  } while (cursor);
  return records;
}

async function proveCredential(message) {
  const delegation = await xrpcJSON(
    "com.atproto.space.getDelegationToken",
    "GET",
    { space },
  );
  const key = await JoseKey.generate(["ES256"]);
  const credential = await exchangeCredential(delegation.token, space, key);
  const query = xrpcURL("com.atproto.space.getRecord", {
    space,
    repo: account.did,
    collection: MESSAGE,
    rkey: message.rkey,
  });
  const read = await credentialFetch(query, credential, key);
  if (!read.ok) throw new Error(`DPoP credential read failed with HTTP ${read.status}`);

  const wrongKey = await JoseKey.generate(["ES256"]);
  await expectXrpcError(
    await credentialFetch(query, credential, wrongKey),
    401,
    "DpopKeyMismatch",
    "wrong DPoP key",
  );
  const wrongSpaceQuery = new URL(query);
  wrongSpaceQuery.searchParams.set("space", wrongSpace);
  await expectXrpcError(
    await credentialFetch(wrongSpaceQuery, credential, key),
    400,
    "InvalidCredential",
    "wrong space credential use",
  );

  const replayDelegation = await xrpcJSON(
    "com.atproto.space.getDelegationToken",
    "GET",
    { space },
  );
  const replayKey = await JoseKey.generate(["ES256"]);
  await exchangeCredential(replayDelegation.token, space, replayKey);
  await expectXrpcError(
    await exchangeResponse(replayDelegation.token, space, replayKey),
    401,
    "JwtReplayed",
    "delegation replay",
  );

  const wrongDelegation = await xrpcJSON(
    "com.atproto.space.getDelegationToken",
    "GET",
    { space },
  );
  await expectXrpcError(
    await exchangeResponse(
      wrongDelegation.token,
      wrongSpace,
      await JoseKey.generate(["ES256"]),
    ),
    400,
    "InvalidDelegationToken",
    "delegation subject mismatch",
  );
  return {
    spaceCredentialIssued: true,
    dpopReadVerified: true,
    wrongKeyRejected: true,
    wrongSpaceRejected: true,
    delegationReplayRejected: true,
    delegationWrongSpaceRejected: true,
  };
}

async function proveAtomicRollback() {
  const probeRkey = "atomic-rollback-probe";
  const response = await applyWritesResponse([
    {
      $type: "com.atproto.space.applyWrites#create",
      collection: FOLDER,
      rkey: probeRkey,
      value: {
        $type: FOLDER,
        name: "must-not-commit",
        revision: 1,
        updatedAt: "2026-08-20T00:00:00Z",
      },
    },
    {
      $type: "com.atproto.space.applyWrites#update",
      collection: STATE,
      rkey: "guaranteed-absent-atomic-probe",
      value: stateValue("guaranteed-absent-atomic-probe", 1),
    },
  ]);
  await expectXrpcError(response, 400, "RecordNotFound", "atomic rollback probe");
  if (await getRecord(FOLDER, probeRkey, authorization, true)) {
    throw new Error("failed applyWrites batch committed its valid create");
  }
  return true;
}

async function proveMissingCAS(message) {
  const stored = await getRecord(STATE, message.rkey, authorization);
  await applyWrites([
    {
      $type: "com.atproto.space.applyWrites#update",
      collection: STATE,
      rkey: message.rkey,
      swapRecord: stored.cid,
      value: stateValue(message.rkey, 2),
    },
  ]);
  const stale = await applyWritesResponse([
    {
      $type: "com.atproto.space.applyWrites#update",
      collection: STATE,
      rkey: message.rkey,
      swapRecord: stored.cid,
      value: stateValue(message.rkey, 3),
    },
  ]);
  if (!stale.ok) return false;
  const overwritten = await getRecord(STATE, message.rkey, authorization);
  return overwritten.value?.revision === 3;
}

function stateValue(rkey, revision) {
  return {
    $type: STATE,
    message: rkey,
    mailboxIds: [folderRkey],
    keywords: [],
    revision,
    updatedAt: `2026-08-20T00:00:0${revision}Z`,
  };
}

async function uploadBlob(raw) {
  const response = await fetch(xrpcURL("com.atproto.repo.uploadBlob"), {
    method: "POST",
    redirect: "error",
    headers: {
      authorization,
      "content-type": "message/rfc822",
    },
    body: raw,
  });
  const body = await response.json();
  if (!response.ok || body.blob?.mimeType !== "message/rfc822") {
    throw new Error(`uploadBlob failed with HTTP ${response.status}`);
  }
  return body.blob;
}

async function getRecord(collection, rkey, auth, notFoundOK = false) {
  const response = await fetch(
    xrpcURL("com.atproto.space.getRecord", {
      space,
      repo: account.did,
      collection,
      rkey,
    }),
    { redirect: "error", headers: { authorization: auth } },
  );
  const body = await response.json();
  if (
    notFoundOK &&
    (response.status === 400 || response.status === 404) &&
    (body.error === "RecordNotFound" || body.error === "RepoNotFound")
  ) {
    return undefined;
  }
  if (!response.ok) throw new Error(`getRecord failed with HTTP ${response.status}`);
  return body;
}

async function applyWrites(writes) {
  const response = await applyWritesResponse(writes);
  const body = await response.json();
  if (!response.ok) throw new Error(`applyWrites failed with HTTP ${response.status}`);
  return body;
}

function applyWritesResponse(writes) {
  return fetch(xrpcURL("com.atproto.space.applyWrites"), {
    method: "POST",
    redirect: "error",
    headers: { authorization, "content-type": "application/json" },
    body: JSON.stringify({ space, repo: account.did, validate: false, writes }),
  });
}

async function exchangeCredential(token, targetSpace, key) {
  const response = await exchangeResponse(token, targetSpace, key);
  const body = await response.json();
  if (!response.ok || typeof body.credential !== "string" || !body.credential) {
    throw new Error(`credential exchange failed with HTTP ${response.status}`);
  }
  return body.credential;
}

async function exchangeResponse(token, targetSpace, key) {
  const request = new Request(xrpcURL("com.atproto.space.getSpaceCredential"), {
    method: "POST",
    redirect: "error",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ space: targetSpace }),
  });
  request.headers.set(
    "dpop",
    await createDpopProof(key, { htm: request.method, htu: request.url }),
  );
  return fetch(request);
}

async function credentialFetch(url, token, key) {
  const request = new Request(url, { redirect: "error" });
  request.headers.set("authorization", `DPoP ${token}`);
  request.headers.set(
    "dpop",
    await createDpopProof(key, {
      htm: request.method,
      htu: request.url,
      credential: token,
    }),
  );
  return fetch(request);
}

async function expectXrpcError(response, status, error, context) {
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error(`${context} returned a non-JSON HTTP ${response.status} response`);
  }
  if (response.status !== status || body?.error !== error) {
    throw new Error(
      `${context} returned HTTP ${response.status} ${String(body?.error)}, expected HTTP ${status} ${error}`,
    );
  }
}

async function xrpcJSON(nsid, method, query, body, auth = authorization) {
  const response = await fetch(xrpcURL(nsid, query), {
    method,
    redirect: "error",
    headers: {
      authorization: auth,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(`${nsid} failed with HTTP ${response.status}`);
  return value;
}

function xrpcURL(nsid, query) {
  const url = new URL(`/xrpc/${nsid}`, origin);
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url;
}

function syntheticMessage(index) {
  const serial = String(index + 1).padStart(3, "0");
  const sourceKey = `synthetic-${serial}`;
  const messageID = `comail-alpha-${serial}@synthetic.invalid`;
  const raw = Buffer.from(
    `Message-ID: <${messageID}>\r\nSubject: Comail alpha proof ${serial}\r\nFrom: sender@synthetic.invalid\r\nTo: recipient@synthetic.invalid\r\n\r\nDisposable synthetic message ${serial}.\r\n`,
  );
  const fingerprint = crypto.createHash("sha256");
  fingerprint.update("comail-habitat-delivery-v2\0");
  fingerprint.update(account.did);
  fingerprint.update("\0");
  fingerprint.update(sourceKey);
  fingerprint.update("\0");
  fingerprint.update(raw);
  return {
    sourceKey,
    messageID,
    raw,
    rawSHA256: sha256(raw),
    rkey: `sha256-${fingerprint.digest("hex")}`,
  };
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
