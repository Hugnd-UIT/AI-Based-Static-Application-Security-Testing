const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const REPO_OWNER = 'Hugnd-UIT';
const REPO_NAME = 'AI-Based-Static-Application-Security-Testing';

// ANSI Colors
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const DIM = '\x1b[90m';
const WHITE = '\x1b[0m';
const BOLD_WHITE = '\x1b[97m';

function print(msg) {
    console.log(msg);
}

// Header
print('');
print(`${CYAN}╭────────────────────────────────────────────────────────────────────╮${WHITE}`);
print(`${CYAN}│ SINFUL SAST · INSTALLER                                            │${WHITE}`);
print(`${DIM}│ Command-line SAST                                                  │${WHITE}`);
print(`${CYAN}╰────────────────────────────────────────────────────────────────────╯${WHITE}`);
print('');
print(`${CYAN}━━━ INSTALLATION ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${WHITE}`);
print('');

// Directory
const installDir = path.join(require('os').homedir(), '.sinful');
print(`├─ Directory`);
print(`${DIM}│  └─ ${installDir}${WHITE}`);
print(`│`);

if (!fs.existsSync(installDir)) {
    fs.mkdirSync(installDir, { recursive: true });
}

// OS detection
const platform = process.platform;
let exeName = '';
if (platform === 'win32') exeName = 'sinful.exe';
else if (platform === 'darwin') exeName = 'sinful-macos';
else exeName = 'sinful-linux';

const exePath = path.join(installDir, platform === 'win32' ? 'sinful.exe' : 'sinful');
const downloadUrl = `https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${exeName}`;

// Release
print(`├─ Release`);
print(`${DIM}│  ├─ Channel      latest${WHITE}`);
print(`${DIM}│  └─ Package      ${exeName}${WHITE}`);
print(`│`);

// Download
function downloadFile(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        const request = https.get(url, (response) => {
            if (response.statusCode === 301 || response.statusCode === 302) {
                return downloadFile(response.headers.location, dest).then(resolve).catch(reject);
            }
            if (response.statusCode !== 200) {
                return reject(new Error(`Status code: ${response.statusCode}`));
            }
            response.pipe(file);
            file.on('finish', () => {
                file.close();
                if (platform !== 'win32') {
                    fs.chmodSync(dest, '755');
                }
                resolve();
            });
        }).on('error', (err) => {
            fs.unlink(dest, () => { });
            reject(err);
        });
    });
}

async function run() {
    print(`├─ Download`);
    let downloadSuccess = false;
    try {
        await downloadFile(downloadUrl, exePath);
        print(`│  └─ ${GREEN}✓ COMPLETED${WHITE}`);
        downloadSuccess = true;
    } catch (err) {
        print(`│  └─ ${RED}✖ FAILED${WHITE}`);
    }
    print(`│`);

    // PATH
    print(`└─ PATH`);
    print(`   └─ ${GREEN}✓ MANAGED BY NPM${WHITE}`);

    print('');
    print('');
    print(`${CYAN}━━━ STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${WHITE}`);
    print('');

    if (!downloadSuccess) {
        print(`${RED}✖ INSTALLATION FAILED${WHITE}`);
        print('');
        print(`├─ Sinful`);
        print(`│  └─ ${RED}✖ Installation could not be completed${WHITE}`);
        print(`│`);
        print(`└─ Reason`);
        print(`   └─ ${DIM}Unable to download the latest release${WHITE}`);
        print('');
        print(`${DIM}Please check your network connection and try again.${WHITE}`);
        print('');
        print(`${DIM}Exit code: 1${WHITE}`);
        process.exit(1);
    }

    // Check Semgrep
    let hasDependencies = true;
    try {
        execSync(platform === 'win32' ? 'where semgrep' : 'which semgrep', { stdio: 'ignore' });
    } catch (e) {
        hasDependencies = false;
        print(`    -> ${YELLOW}[!] Semgrep not found. Run: pip install semgrep${WHITE}`);
    }
    
    try {
        execSync(platform === 'win32' ? 'where git' : 'which git', { stdio: 'ignore' });
    } catch (e) {
        hasDependencies = false;
        print(`    -> ${YELLOW}[!] Git not found. Needed for scanning remote URLs.${WHITE}`);
    }

    if (hasDependencies) {
        print(`${GREEN}✓ INSTALLATION COMPLETE${WHITE}`);
        print('');
        print(`├─ Sinful`);
        print(`│  └─ ${GREEN}✓ Installed successfully${WHITE}`);
        print(`│`);
        print(`└─ Environment`);
        print(`   └─ ${GREEN}✓ Ready${WHITE}`);
        print('');
    } else {
        print(`${YELLOW}⚠ INSTALLATION COMPLETE${WHITE}`);
        print('');
        print(`├─ Sinful`);
        print(`│  └─ ${GREEN}✓ Installed successfully${WHITE}`);
        print(`│`);
        print(`└─ Environment`);
        print(`   └─ ${YELLOW}⚠ Some dependencies are missing${WHITE}`);
        print('');
        print(`${DIM}Sinful was installed successfully, but some dependencies are missing.${WHITE}`);
        print('');
    }

    print(`${DIM}Run: ${BOLD_WHITE}sinful${WHITE}`);
    print('');
}

run();
