const fs = require('../services/fs');

exports.readFile = (req, res) => {
    const filename = req.query.file;
    fs.read(filename, (err, data) => {
        if (err) return res.status(500).send('Error');
        res.send(data);
    });
};
