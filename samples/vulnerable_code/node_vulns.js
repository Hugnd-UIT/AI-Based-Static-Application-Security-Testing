const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql');
const fs = require('fs');
const serialize = require('node-serialize');

const app = express();

// Hardcoded Password
const dbPassword = "super_secret_admin_password_123";

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'admin',
    password: dbPassword,
    database: 'test'
});

app.get('/search', (req, res) => {
    let username = req.query.username;
    // SQL Injection
    let query = "SELECT * FROM users WHERE username = '" + username + "'";
    connection.query(query, (err, results) => {
        if (err) throw err;
        // Reflected XSS
        res.send("<div>Results for: " + username + "<br>" + JSON.stringify(results) + "</div>");
    });
});

app.get('/system', (req, res) => {
    let cmd = req.query.cmd;
    // Command Injection
    exec("ls -l " + cmd, (error, stdout, stderr) => {
        res.send(`<pre>${stdout}</pre>`);
    });
});

app.get('/file', (req, res) => {
    let file = req.query.file;
    // Path Traversal
    let filepath = __dirname + "/public/" + file;
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) return res.send("Error");
        res.send(data);
    });
});

app.get('/deserialize', (req, res) => {
    let payload = req.query.payload;
    // Insecure Deserialization
    let obj = serialize.unserialize(payload);
    res.send("Deserialized object");
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
