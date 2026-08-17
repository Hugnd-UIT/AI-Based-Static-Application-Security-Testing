#!/usr/bin/env node
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const installDir = path.join(os.homedir(), '.sinful');
const platform = process.platform;
const exeName = platform === 'win32' ? 'sinful.exe' : 'sinful';
const exePath = path.join(installDir, exeName);

if (!fs.existsSync(exePath)) {
    console.error(`[!] Sinful executable not found at ${exePath}`);
    console.error(`Please run the installation again.`);
    process.exit(1);
}

const args = process.argv.slice(2);
const result = spawnSync(exePath, args, { stdio: 'inherit' });

process.exit(result.status || 0);
