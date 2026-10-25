import { execFile } from "node:child_process";
import { win32 } from "node:path";
import { createHash } from "node:crypto";
import { isTestHomeGuardArmed } from "../../lib/test-home-guard";
import { resolveTrustedWindowsPowerShellExe } from "../../lib/windows-elevation";
import type { DesktopAppInstall } from "../desktop-app/types";

export const DESKTOP_COMPATIBILITY_ASSESSED_VERSION = "26.924.2738.0";
export const DESKTOP_COMPATIBILITY_ASSESSED_FAMILY = "OpenAI.Codex_2p2nqsd0c76g0";

/** Internal observation only; never returned by management status. */
export interface DesktopPackageObservation extends DesktopAppInstall {
  proof?: { packageFullName: string; publisherId: string; publisher: string; manifestName: string;
    manifestPublisher: string; manifestVersion: string; appId: string; executable: string;
    canonicalExecutable: string; manifestDigest: string; executableIdentity: string };
}

// Compatibility-only read: do not alter general discovery or execute/activate the application.
export const DESKTOP_PACKAGE_PROOF_SCRIPT = [
  "$ErrorActionPreference='Stop'; Import-Module Appx -ErrorAction Stop",
  "$packages=@(Get-AppxPackage -Name OpenAI.Codex)",
  "if($packages.Count -ne 1){throw 'Package not unique'}; $p=$packages[0]",
  "$root=Get-Item -LiteralPath $p.InstallLocation; $app=Get-Item -LiteralPath (Join-Path $root.FullName 'app')",
  "$exe=Get-Item -LiteralPath (Join-Path $app.FullName 'ChatGPT.exe')",
  "foreach($item in @($root,$app,$exe)){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse identity'}}",
  "if(-not $root.PSIsContainer -or -not $app.PSIsContainer -or $exe.PSIsContainer){throw 'Wrong file kind'}",
  "$manifest=Get-AppxPackageManifest -Package $p.PackageFullName",
  "$entry=@($manifest.Package.Applications.Application|Where-Object {$_.Id -eq 'App'})",
  "if($entry.Count -ne 1){throw 'App not unique'}; $entry=$entry[0]",
  "$xml=[Text.Encoding]::UTF8.GetBytes($manifest.OuterXml); if($xml.Length -gt 1048576){throw 'Manifest too large'}",
  "$sha=[Security.Cryptography.SHA256]::Create(); try{$digest=([BitConverter]::ToString($sha.ComputeHash($xml))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}",
  "$again=@(Get-AppxPackage -Name OpenAI.Codex); $exeAgain=Get-Item -LiteralPath $exe.FullName",
  "if($again.Count -ne 1 -or $again[0].PackageFullName -cne $p.PackageFullName -or $again[0].Publisher -cne $p.Publisher -or $again[0].InstallLocation -ine $p.InstallLocation -or ($exeAgain.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $exeAgain.Length -ne $exe.Length -or $exeAgain.CreationTimeUtc.Ticks -ne $exe.CreationTimeUtc.Ticks -or $exeAgain.LastWriteTimeUtc.Ticks -ne $exe.LastWriteTimeUtc.Ticks){throw 'Package changed during proof'}",
  "[pscustomobject]@{id=$p.PackageFamilyName;root=$root.FullName;relaunch=$p.PackageFamilyName+'!App';proof=@{packageFullName=$p.PackageFullName;publisherId=$p.PublisherId;publisher=$p.Publisher;manifestName=[string]$manifest.Package.Identity.Name;manifestPublisher=[string]$manifest.Package.Identity.Publisher;manifestVersion=[string]$manifest.Package.Identity.Version;appId=[string]$entry.Id;executable=[string]$entry.Executable;canonicalExecutable=$exe.FullName;manifestDigest=$digest;executableIdentity=([string]$exe.Length+':'+$exe.CreationTimeUtc.Ticks+':'+$exe.LastWriteTimeUtc.Ticks)}}|ConvertTo-Json -Depth 3 -Compress",
].join("; ");

/** Last completed probe outcome. Only public package facts: never paths, keys or account data. */
export interface DesktopBuildAssessment {
  assessedVersion: string;
  observedVersion: string | null;
  verified: boolean;
  completedAt: number;
}

function assessInstalledPackage(install: DesktopPackageObservation): { observedVersion: string | null; verified: boolean; identity: string | null } {
  const name = win32.basename(install.root);
  const parts = /^OpenAI\.Codex_(\d+\.\d+\.\d+\.\d+)_(x64|arm64|x86|neutral)_([A-Za-z0-9.-]*)_([A-Za-z0-9]+)$/.exec(name);
  const identified = install.id === DESKTOP_COMPATIBILITY_ASSESSED_FAMILY && install.relaunch === `${install.id}!App`
    && !!parts && `OpenAI.Codex_${parts[4]}` === install.id;
  const observedVersion = identified ? parts![1] : null;
  const proof = install.proof;
  const verified = identified && observedVersion === DESKTOP_COMPATIBILITY_ASSESSED_VERSION && !!proof
    && /^[A-Za-z]:\\/.test(install.root) && win32.normalize(install.root) === install.root
    && proof.packageFullName === name && proof.publisherId === "2p2nqsd0c76g0"
    && typeof proof.publisher === "string" && proof.publisher.length > 0 && proof.publisher.length <= 1024
    && proof.manifestName === "OpenAI.Codex" && proof.manifestPublisher === proof.publisher
    && proof.manifestVersion === observedVersion && proof.appId === "App"
    && typeof proof.executable === "string" && proof.executable.replaceAll("/", "\\").toLowerCase() === "app\\chatgpt.exe"
    && proof.canonicalExecutable === win32.join(install.root, "app", "ChatGPT.exe")
    && /^[a-f0-9]{64}$/.test(proof.manifestDigest) && /^\d{1,16}:\d{1,20}:\d{1,20}$/.test(proof.executableIdentity);
  const identity = verified && proof ? createHash("sha256").update(JSON.stringify([install.id, install.root, install.relaunch,
    proof.packageFullName, proof.publisherId, proof.publisher, proof.manifestName, proof.manifestPublisher,
    proof.manifestVersion, proof.appId, proof.executable, proof.canonicalExecutable, proof.manifestDigest,
    proof.executableIdentity])).digest("hex") : null;
  return { observedVersion, verified, identity };
}

/** Resolve only after the exact asynchronous child has closed, including abort/timeout. */
function queryInstalledPackage(signal: AbortSignal): Promise<DesktopPackageObservation | null> {
  if (process.platform !== "win32" || isTestHomeGuardArmed() || signal.aborted) return Promise.resolve(null);
  return new Promise(resolve => {
    let completed = false, closed = false, result: DesktopPackageObservation | null = null;
    const finish = () => { if (completed && closed) { signal.removeEventListener("abort", abort); resolve(result); } };
    const child = execFile(resolveTrustedWindowsPowerShellExe(), ["-NoProfile", "-NonInteractive", "-Command", DESKTOP_PACKAGE_PROOF_SCRIPT], {
      timeout: 10000, maxBuffer: 65536, encoding: "utf8", windowsHide: true,
    }, (error, stdout) => {
      try {
        const value = error ? null : JSON.parse(stdout);
        if (value && typeof value === "object" && !Array.isArray(value) && typeof value.id === "string"
          && typeof value.root === "string" && typeof value.relaunch === "string"
          && value.proof && typeof value.proof === "object" && !Array.isArray(value.proof)) result = value;
      } catch { /* An unverifiable package never inherits a completed success. */ }
      completed = true; finish();
    });
    const abort = () => { try { child.kill(); } catch { /* Keep ownership until execFile reports close. */ } };
    child.once("close", () => { closed = true; finish(); });
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Coalesce concurrent fresh probes; never cache a positive verdict across requests. */
export function createInstalledBuildProbe(query: (signal: AbortSignal) => Promise<DesktopPackageObservation | null> = queryInstalledPackage) {
  let pending: Promise<boolean> | null = null, controller: AbortController | null = null, closed = false;
  let lastResult: DesktopBuildAssessment | null = null;
  let identity: string | null = null, revision = 0;
  const record = (install: DesktopPackageObservation | null) => {
    const outcome = install ? assessInstalledPackage(install) : { observedVersion: null, verified: false, identity: null };
    if (outcome.identity !== identity) { identity = outcome.identity; revision++; }
    lastResult = { assessedVersion: DESKTOP_COMPATIBILITY_ASSESSED_VERSION, observedVersion: outcome.observedVersion,
      verified: outcome.verified, completedAt: Date.now() };
    return outcome.verified;
  };
  return {
    check(): Promise<boolean> {
      if (closed) return Promise.resolve(false);
      if (pending) return pending;
      const current = new AbortController(); controller = current;
      pending = Promise.resolve().then(() => current.signal.aborted ? null : query(current.signal))
        .then(install => closed || current.signal.aborted ? false : record(install))
        .catch(() => closed || current.signal.aborted ? false : record(null))
        .finally(() => { pending = null; controller = null; });
      return pending;
    },
    /** Last completed check only: an aborted or in-flight query never rewrites it. */
    lastResult(): DesktopBuildAssessment | null { return lastResult ? { ...lastResult } : null; },
    /** Private consent fence: a completed A->B->A proof is distinct from unchanged A. */
    binding() { return { identity, revision }; },
    async close(): Promise<void> { closed = true; identity = null; revision++; controller?.abort(); await pending; },
  };
}

export async function isAssessedDesktopInstalled(): Promise<boolean> {
  const probe = createInstalledBuildProbe();
  try { return await probe.check(); } finally { await probe.close(); }
}
