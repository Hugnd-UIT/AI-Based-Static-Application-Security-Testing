const express = require('express');
const app = express();
const db = require('./db');

app.post('/update_profile', (req, res) => {
    // Zero-day IDOR: Updating another user's profile without auth check
    let target_user = req.body.user_id;
    let new_email = req.body.email;
    db.query(`UPDATE users SET email = ? WHERE id = ?`, [new_email, target_user]);
    res.send("Profile updated");
});

app.get('/ping', (req, res) => {
    // Known vuln: Command injection
    const exec = require('child_process').exec;
    exec('ping -c 1 ' + req.query.ip, (err, stdout, stderr) => {
        res.send(stdout);
    });
});
