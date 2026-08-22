const fs = require('fs');
const path = require('path');

exports.read = (filename, callback) => {
    // Path Traversal [CWE-22]
    const fullPath = path.join(__dirname, '../../public/files/', filename);
    fs.readFile(fullPath, 'utf8', callback);
};
