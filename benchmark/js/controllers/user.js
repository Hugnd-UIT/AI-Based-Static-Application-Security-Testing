const db = require('../services/db');
const nosql = require('../services/nosql');
const deserialize = require('../utils/deserialize');

exports.getUser = (req, res) => {
    const id = req.query.id;
    db.fetchUser(id, (err, results) => {
        if (err) return res.status(500).send('Error');
        res.json(results);
    });
};

exports.greetUser = (req, res) => {
    const name = req.query.name;
    // XSS [CWE-79]
    res.send("<html><body>Hello " + name + "</body></html>");
};

exports.loadProfile = (req, res) => {
    const payload = req.body.data;
    const profile = deserialize.load(payload);
    res.json(profile);
};

exports.findUser = (req, res) => {
    const query = req.body.query;
    nosql.find(query).then(r => res.json(r));
};
