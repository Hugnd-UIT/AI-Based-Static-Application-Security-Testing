const http = require('http');

exports.get = (url, cb) => {
    // Server-Side Request Forgery [CWE-918]
    http.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => cb(data));
    }).on('error', () => cb('Error'));
};
