const execUtil = require('../utils/exec');
const configUtil = require('../utils/config');
const httpUtil = require('../utils/http');

exports.pingHost = (req, res) => {
    const target = req.query.target;
    execUtil.runPing(target, (err, output) => {
        if (err) return res.status(500).send('Failed');
        res.send(output);
    });
};

exports.updateConfig = (req, res) => {
    const data = req.body;
    configUtil.applyConfig(data);
    res.send('Updated');
};

exports.fetchUrl = (req, res) => {
    const url = req.query.url;
    httpUtil.get(url, (data) => {
        res.send(data);
    });
};
