const mysql = require('mysql');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'test'
});

exports.fetchUser = (id, callback) => {
    // SQL Injection [CWE-89]
    const query = "SELECT * FROM users WHERE id = " + id;
    connection.query(query, callback);
};
