import fs from "node:fs";
import http from "node:http";
import https from "node:https";

const key = fs.readFileSync(required("TLS_KEY_FILE"));
const cert = fs.readFileSync(required("TLS_CERT_FILE"));

const server = https.createServer({ key, cert }, (request, response) => {
  const upstream = http.request(
    {
      hostname: "127.0.0.1",
      port: 2583,
      method: request.method,
      path: request.url,
      headers: request.headers,
    },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on("error", () => {
    if (!response.headersSent) response.writeHead(502);
    response.end();
  });
  request.pipe(upstream);
});

server.listen(443, "0.0.0.0");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}
