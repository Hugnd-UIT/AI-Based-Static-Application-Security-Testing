const authUtil = require('../utils/auth');

exports.login = (req, res) => {
    const user = req.body.username;
    const pass = req.body.password;
    if (authUtil.verify(user, pass)) {
        res.send('Success');
    } else {
        res.send('Fail');
    }
};

exports.redirect = (req, res) => {
    const target = req.query.url;
    // Open Redirect [CWE-601]
    res.redirect(target);
};
