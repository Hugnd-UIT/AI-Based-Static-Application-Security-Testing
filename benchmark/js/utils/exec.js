const { exec } = require('child_process');

exports.runPing = (host, callback) => {
    // Command Injection [CWE-78]
    const cmd = "ping -c 4 " + host;
    exec(cmd, callback);
};
