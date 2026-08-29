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

    // lodash
    _.merge({}, JSON.parse(payload));

    // node-serialize
    serialize.unserialize(payload);

    // minimist
    minimist(payload.split(' '));

    // handlebars
    handlebars.compile(payload);

    // express

    res.send("Success");
});

module.exports = router;
