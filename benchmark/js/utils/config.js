const _ = require('lodash');

let globalConfig = {
    theme: 'dark',
    lang: 'en'
};

exports.applyConfig = (newSettings) => {
    // Prototype Pollution [CWE-1321]
    _.merge(globalConfig, newSettings);
};
