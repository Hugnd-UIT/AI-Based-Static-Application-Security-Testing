const express = require('express');
const user = require('../controllers/user');
const system = require('../controllers/system');
const file = require('../controllers/file');
const auth = require('../controllers/auth');

const router = express.Router();

router.get('/user', user.getUser);
router.get('/greet', user.greetUser);
router.post('/profile', user.loadProfile);
router.post('/find', user.findUser);

router.post('/config', system.updateConfig);
router.get('/ping', system.pingHost);
router.get('/fetch', system.fetchUrl);

router.get('/read', file.readFile);

router.get('/login', auth.login);
router.get('/redirect', auth.redirect);

const _ = require('lodash');
const serialize = require('node-serialize');
const minimist = require('minimist');
const handlebars = require('handlebars');

router.get('/sca', (req, res) => {
    const payload = req.query.payload || "{}";

    // CVE-2019-10744 (lodash) Prototype Pollution
    _.merge({}, JSON.parse(payload));

    // CVE-2017-5941 (node-serialize) Deserialization RCE
    serialize.unserialize(payload);

    // CVE-2020-7598 (minimist) Prototype Pollution
    minimist(JSON.parse(payload));

    // CVE-2021-23369 (handlebars) AST injection RCE
    const template = handlebars.compile(payload);
    template({});

    // CVE-2022-23628 (jsonwebtoken)
    const jwt = require('jsonwebtoken');
    jwt.verify(payload, "secret");

    res.send("Success");
});

module.exports = router;
