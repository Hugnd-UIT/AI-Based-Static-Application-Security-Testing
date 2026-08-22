const serialize = require('node-serialize');

exports.load = (payload) => {
    // Deserialization [CWE-502]
    return serialize.unserialize(payload);
};
