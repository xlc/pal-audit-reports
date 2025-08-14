// run with: bun run run.ts [--verbose]
import { readdir, unlink, access } from "node:fs/promises";
import { resolve, dirname, basename, join } from "node:path";
import { performance } from "node:perf_hooks";

const VERBOSE = process.argv.includes("--verbose") || process.env.VERBOSE === "1";

function nowISO() { return new Date().toISOString(); }
function log(...a: any[]) { console.log(`[${nowISO()}]`, ...a); }
function warn(...a: any[]) { console.warn(`[${nowISO()}] WARN`, ...a); }
function error(...a: any[]) { console.error(`[${nowISO()}] ERROR`, ...a); }
function v(...a: any[]) { if (VERBOSE) log(...a); }

async function findPdfPathsRecursive(root: string): Promise<string[]> {
  const results: string[] = [];
  const t0 = performance.now();

  async function walk(dir: string) {
    v("scan dir:", dir);
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (e: any) {
      warn("skip unreadable dir:", dir, "-", e?.message || e);
      return;
    }
    for (const e of entries) {
      const full = resolve(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" || e.name === ".git") { v("skip dir:", full); continue; }
        await walk(full);
      } else if (e.isFile() && /\.pdf$/i.test(e.name)) {
        results.push(full);
        v("found pdf:", full);
      }
    }
  }

  await walk(root);
  log("discovered pdfs:", results.length, "in", Math.round(performance.now() - t0), "ms");
  if (VERBOSE) for (const p of results) console.log("  -", p);
  return results;
}

function jsonPathForPdf(pdfPath: string): string {
  const dir = dirname(pdfPath);
  const base = basename(pdfPath).replace(/\.[^.]+$/i, "");
  return join(dir, `${base}.json`);
}

async function fileExists(p: string): Promise<boolean> {
  try { await access(p); return true; } catch { return false; }
}

const prompt = `
Analyze the attached PDF audit report and extract every identified issue/finding as a structured JSON array. Your output must be ONLY a valid JSON array (no prose, no Markdown).

NOTE: The provided PDF is an example audit report. Do not hardcode section names or formats. The extraction must generalize to different report structures and terminology.

Schema (required keys for each item):
- "id": If the report provides a unique identifier/reference for the finding (e.g., "ID: ACALA-01", "Finding #3", "SR-2021-001"), use it EXACTLY as written (trim leading/trailing whitespace; do not change case or normalize). If no identifier is provided, generate a deterministic URL-safe ID as:
  kebab-case(title) + "--" + kebab-case(component or "unspecified") + "--" + lowercase(severity)
  Kebab-case uses only [a-z0-9-], converting other characters to "-", collapsing repeats, and trimming leading/trailing "-".
  Ensure uniqueness within the array. If a duplicate ID (provided or generated) would occur, append "--2", "--3", etc., preserving the base ID.
- "title": Short, specific issue name from the report.
- "severity": One of ["Critical","High","Medium","Low","Informational","Unknown"]. Map report-specific ratings to this scale (e.g., Blocker/Severe -> Critical; Major -> High; Moderate -> Medium; Minor -> Low; Info/Note -> Informational). If unclear, use "Unknown".
- "component": The affected system/module/asset (e.g., API Gateway, Auth Service, Smart Contract X). If not stated, use "unspecified".
- "description": 2–4 sentences summarizing what the issue is and how it was identified. Use facts and wording from the report; do not invent details.
- "impact": 1–2 sentences describing realistic consequences if exploited.
- "kind": One of ["Design","Implementation","Configuration","Cryptography","Access Control","Authentication","Authorization","Input Validation","Dependency","Network","Operational","Documentation","Process"]. Pick the single best fit.

Extraction rules:
1) Parse all sections that may contain issues (e.g., Findings, Vulnerabilities, Issues, Risks, Security Observations, Weaknesses, Test Results).
2) Capture a report-provided ID wherever present, including in headings, tables, captions, sidebars, footnotes, or tags (e.g., "Finding AC-05", "Issue ID", "Ref", "Ticket", "Observation #").
3) Include every distinct issue; deduplicate near-identical items (merge details).
4) Split combined findings into separate items if they describe different root causes or components.
5) Keep technical identifiers (e.g., CVEs, CWEs) in "description" only; do not add extra fields.
6) Normalize severities to the specified set; map custom scales accordingly.
7) Include minimal remediation context only if needed to explain the issue; do not add recommendations as separate fields.
8) If a required field is missing in the report, use the specified default ("unspecified" or "Unknown").
9) Ignore non-issue content (executive summaries, methodology, marketing material) unless it contains concrete findings.

Output rules:
- Return a single JSON array of objects that follow the schema above.
- Use double quotes for all JSON strings.
- Do not include nulls or extra keys.
- Ensure valid JSON (no trailing commas).
- Ensure each "id" is unique within the array.
- If no issues are found, return [].

Example output (illustrative only):
[
  {
    "id": "ACALA-01",
    "title": "Weak password policy on admin portal",
    "severity": "High",
    "component": "Admin Portal",
    "description": "The audit found that the admin portal accepts passwords with fewer than eight characters and lacks complexity checks. Password reuse across accounts was not prevented as observed in test accounts.",
    "impact": "Increases likelihood of credential stuffing and brute-force compromise of privileged accounts.",
    "kind": "Authentication"
  },
  {
    "id": "outdated-library-vulnerable-to-rce--payment-service--critical",
    "title": "Outdated library vulnerable to RCE",
    "severity": "Critical",
    "component": "Payment Service",
    "description": "The service uses library X v1.2.3 which is affected by a known remote code execution flaw referenced in the report. The vulnerable code path is reachable via the transaction endpoint.",
    "impact": "An attacker could execute arbitrary code on the payment infrastructure, leading to full service compromise.",
    "kind": "Dependency"
  }
]
`;

async function runPolkaWithPath(fullPath: string): Promise<number> {
  const outPath = jsonPathForPdf(fullPath);
  const cmd = process.platform === "win32" ? ["cmd", "/c", "npx @polka-codes/cli --silent"] : ["sh", "-c", "npx @polka-codes/cli --silent"];
  v("spawn cmd:", cmd.join(" "), "for:", fullPath, "->", outPath);

  const t0 = performance.now();
  const proc = Bun.spawn({
    cmd,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "inherit",
  });

  if (!proc.stdin || !proc.stdout) {
    error("stdin/stdout not available for spawned process.");
    return 1;
  }

  const input = `${prompt}\n\n---\n\nProcess PDF: ${fullPath}\n`;
  const bytes = new TextEncoder().encode(input);
  v("writing to stdin bytes:", bytes.byteLength);
  proc.stdin.write(bytes);
  proc.stdin.end();

  const stdoutText = await new Response(proc.stdout).text();
  v("stdout chars:", stdoutText.length > 0 ? stdoutText.length : 0);

  let isJson = false;
  try { JSON.parse(stdoutText); isJson = true; } catch {}
  if (!isJson) {
    warn("stdout is not valid JSON (writing raw anyway):", fullPath);
    if (VERBOSE) console.log("stdout preview:", stdoutText.slice(0, 200).replace(/\s+/g, " "), "...");
  }

  const code = await proc.exited;
  log("polka exit code:", code, "for:", fullPath, "elapsed:", Math.round(performance.now() - t0), "ms");

  if (code !== 0) {
    error("polka failed for:", fullPath);
    try { await unlink(outPath); v("removed incomplete file:", outPath); } catch {}
  } else {
    const written = await Bun.write(outPath, stdoutText);
    log("wrote JSON:", outPath, "bytes:", written);
  }

  return code;
}

const pdfs = await findPdfPathsRecursive(process.cwd());

if (pdfs.length === 0) {
  warn("No PDF files found in current directory (recursive).");
  process.exit(0);
}

log("processing", pdfs.length, "pdf(s)...");
for (let i = 0; i < pdfs.length; i++) {
  const p = pdfs[i];
  const outPath = jsonPathForPdf(p);
  log(`file ${i + 1}/${pdfs.length}:`, p);

  // Skip if JSON already exists next to the PDF
  if (await fileExists(outPath)) {
    log("skip existing JSON:", outPath);
    continue;
  }

  try {
    const code = await runPolkaWithPath(p);
    if (code !== 0) warn("continuing after failure for:", p);
  } catch (e: any) {
    error("unhandled error for:", p, "-", e?.stack || e?.message || e);
  }
}
log("done.");