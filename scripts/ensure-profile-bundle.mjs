#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";

const [, , manifestPath, bundleName = "dsh-purge", mode = "apply"] = process.argv;

function fail(message) {
  console.error(`[dsh-purge] ${message}`);
  process.exitCode = 1;
}

if (!manifestPath) {
  fail("usage: ensure-profile-bundle.mjs <profile/package.json> [bundle] [check|apply]");
} else {
  const absolute = path.resolve(manifestPath);
  let raw;
  let manifest;
  try {
    raw = fs.readFileSync(absolute, "utf8");
    manifest = JSON.parse(raw);
  } catch (error) {
    fail(`cannot read ${absolute}: ${error.message}`);
  }

  if (manifest && (typeof manifest !== "object" || Array.isArray(manifest))) {
    fail(`${absolute} must contain a JSON object`);
  } else if (manifest) {
    const profile = manifest.dsh?.profile;
    const bundles = profile?.bundles;
    if (!profile || typeof profile !== "object" || Array.isArray(profile) || !Array.isArray(bundles)) {
      fail(`${absolute} has no dsh.profile.bundles array`);
    } else if (bundles.includes(bundleName)) {
      console.log(`[dsh-purge] profile bundle already enabled: ${bundleName}`);
    } else if (mode === "check") {
      console.log(`[dsh-purge] profile bundle missing: ${bundleName}`);
      process.exitCode = 2;
    } else if (mode !== "apply") {
      fail(`unknown mode ${JSON.stringify(mode)}; use check or apply`);
    } else {
      const newline = raw.includes("\r\n") ? "\r\n" : "\n";
      profile.bundles = [...bundles, bundleName];
      const next = JSON.stringify(manifest, null, 2) + newline;
      const temp = `${absolute}.${process.pid}.${Date.now()}.tmp`;
      try {
        fs.writeFileSync(temp, next, "utf8");
        fs.renameSync(temp, absolute);
        console.log(`[dsh-purge] enabled profile bundle: ${bundleName}`);
      } catch (error) {
        try { fs.unlinkSync(temp); } catch { /* best effort */ }
        fail(`cannot update ${absolute}: ${error.message}`);
      }
    }
  }
}
