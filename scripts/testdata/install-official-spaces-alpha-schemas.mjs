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
    sha256: "0711f09f63e3655eeefd877889cef572d4a23928a679d32abf86f9d585ceecc1",
  },
  {
    id: "email.atmos.messageStateRevision",
    file: "messageStateRevision.json",
    sha256: "1f23c818f896a47eac101f8e283ccb6ceb3f9dd382e205326e42daaf0bdee0a7",
  },
  {
    id: "email.atmos.messageStateOperation",
    file: "messageStateOperation.json",
    sha256: "e0122e8b316f2c4492a5afb9df614fffa07d44893b4a9a43e411c5427c11b51c",
  },
  {
    id: "email.atmos.folderRevision",
    file: "folderRevision.json",
    sha256: "61cd01cdb386a951912498fbf87f83092bf4de9de971d1b09ea9533019d33e84",
  },
  {
    id: "email.atmos.folderOperation",
    file: "folderOperation.json",
    sha256: "398c98a7db2b6d4e0d1294d2009dbdda51b31d270a9d9dfc03dccd0a1bc5dffc",
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
    document.defs?.main?.type !== "record"
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
