import crypto from "node:crypto";
import fs from "node:fs/promises";
import { spawnSync } from "node:child_process";

const preparePath = "/app/packages/pds/dist/repo/prepare.js";
const sourceDirectory = "/tmp/comail-schema-source";
const outputDirectory = "/app/comail-lexicons";
const expectedPrepareSHA256 =
  "625c47436ba5b551e24538dbafc7e28a10597f1d0c7609d8d7b08124c72f4746";
const schemas = [
  {
    id: "email.atmos.message",
    file: "message.json",
    sha256: "dfec09b66d2b64b856bf24f9165f4f1a3b0b6912589f955e5266d2ad632eafbd",
  },
  {
    id: "email.atmos.messageStateRevision",
    file: "messageStateRevision.json",
    sha256: "24e5e48598bd32cba97240b19c09c3576a43a62a13592f77ada55df06ebe17f8",
  },
  {
    id: "email.atmos.messageStateOperation",
    file: "messageStateOperation.json",
    sha256: "0c0d12ec2f818b40a85ebecf14af1fa1fc4a44e260f3ba490cb996639429326b",
  },
  {
    id: "email.atmos.folderRevision",
    file: "folderRevision.json",
    sha256: "7b04352914ab168d69f54b0656b741e50c07287f3d9c3bac20a911407afbd136",
  },
  {
    id: "email.atmos.folderOperation",
    file: "folderOperation.json",
    sha256: "7c2e1a4c144c1c114b627c815d88cf95306240561a748bb5b0aa589582b8986b",
  },
];

const prepare = await fs.readFile(preparePath, "utf8");
assertSHA256("pinned PDS prepare.js", prepare, expectedPrepareSHA256);

const presentFiles = (await fs.readdir(sourceDirectory)).sort();
const expectedFiles = schemas.map(({ file }) => file).sort();
if (JSON.stringify(presentFiles) !== JSON.stringify(expectedFiles)) {
  throw new Error("schema source directory did not contain the exact five pinned files");
}

for (const schema of schemas) {
  const raw = await fs.readFile(`${sourceDirectory}/${schema.file}`, "utf8");
  assertSHA256(schema.id, raw, schema.sha256);
  const document = JSON.parse(raw);
  if (
    document.lexicon !== 1 ||
    document.id !== schema.id ||
    document.defs?.main?.type !== "record" ||
    Object.hasOwn(document, "draft") ||
    !document.defs?.main?.description?.startsWith("ALPHA. ")
  ) {
    throw new Error(`invalid pinned record Lexicon: ${schema.id}`);
  }
}

const generated = spawnSync(
  "/app/node_modules/.bin/ts-lex",
  [
    "build",
    "--lexicons",
    sourceDirectory,
    "--out",
    outputDirectory,
    "--index-file",
    "--pretty=false",
    "--import-ext=.ts",
  ],
  { encoding: "utf8" },
);
if (generated.status !== 0) {
  throw new Error("pinned schema code generation failed");
}

const importMarker = "import { app, chat, com } from '../lexicons/index.js';\n";
const mapMarker = "const knownSchemas = new Map([\n";
if (count(prepare, importMarker) !== 1 || count(prepare, mapMarker) !== 1) {
  throw new Error("pinned PDS prepare.js patch markers drifted");
}
const patched = prepare
  .replace(
    importMarker,
    `${importMarker}import { email as comailEmail } from '/app/comail-lexicons/index.ts';\n`,
  )
  .replace(
    mapMarker,
    `${mapMarker}${schemas
      .map(({ id }) => `    comailEmail.atmos.${id.split(".").at(-1)}.main,`)
      .join("\n")}\n`,
  );
if (
  patched === prepare ||
  count(patched, "comailEmail.atmos.") !== schemas.length ||
  patched.includes("email.atmos.messageState.main") ||
  patched.includes("email.atmos.folder.main")
) {
  throw new Error("pinned PDS prepare.js patch was not exact");
}
await fs.writeFile(preparePath, patched, { encoding: "utf8", mode: 0o644 });

const generatedModule = await import("/app/comail-lexicons/index.ts");
for (const { id } of schemas) {
  const schema = generatedModule.email.atmos[id.split(".").at(-1)]?.main;
  if (schema?.$type !== id) {
    throw new Error(`generated record schema did not bind ${id}`);
  }
}

process.stdout.write(
  JSON.stringify({
    basePrepareSHA256: expectedPrepareSHA256,
    patchedPrepareSHA256: sha256(patched),
    schemas: schemas.map(({ id, sha256 }) => ({ id, sha256 })),
  }),
);

function assertSHA256(label, value, expected) {
  if (sha256(value) !== expected) {
    throw new Error(`${label} SHA-256 did not match the pin`);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function count(value, needle) {
  return value.split(needle).length - 1;
}
