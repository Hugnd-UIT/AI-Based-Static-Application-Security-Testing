const serialize = require('node-serialize');

exports.load = (payload) => {
    // Deserialization of Untrusted Data [CWE-502]
    return serialize.unserialize(payload);
};
