import http from "node:http";
import {
  didForCreateOp,
  formatDidDoc,
  normalizeOp,
} from "/app/node_modules/@did-plc/lib/dist/index.js";

const operations = new Map();

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, "http://plc.test");
  if (request.method === "GET" && url.pathname === "/_health") {
    return json(response, 200, { status: "ok" });
  }

  const [encodedDID, ...suffixParts] = url.pathname.slice(1).split("/");
  const suffix = suffixParts.join("/");
  const did = decodeURIComponent(encodedDID ?? "");
  if (!did.startsWith("did:plc:")) {
    return json(response, 404, { error: "NotFound" });
  }

  if (request.method === "POST" && suffix === "") {
    const operation = await readJSON(request);
    if ((await didForCreateOp(operation)) !== did || operations.has(did)) {
      return json(response, 400, { error: "InvalidOperation" });
    }
    operations.set(did, operation);
    return json(response, 200, {});
  }

  const operation = operations.get(did);
  if (!operation) {
    return json(response, 404, { error: "NotFound" });
  }
  if (request.method === "GET" && suffix === "") {
    const normalized = normalizeOp(operation);
    return json(response, 200, formatDidDoc({ did, ...normalized }));
  }
  if (request.method === "GET" && suffix === "data") {
    const normalized = normalizeOp(operation);
    return json(response, 200, { did, ...normalized });
  }
  if (request.method === "GET" && suffix === "log") {
    return json(response, 200, [operation]);
  }
  if (request.method === "GET" && suffix === "log/last") {
    return json(response, 200, operation);
  }
  return json(response, 404, { error: "NotFound" });
});

server.listen(3001, "0.0.0.0");

function json(response, status, value) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function readJSON(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
