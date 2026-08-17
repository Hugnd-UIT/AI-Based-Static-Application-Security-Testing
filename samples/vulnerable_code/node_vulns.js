const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Vulnerability 1: Cross-Site Scripting (Reflected XSS)
app.get('/search', (req, res) => {
    let query = req.query.q;
    
    // [DATA FLOW] Source -> query -> HTML response
    // SINK
    res.render('search', { query: sanitizeHtml(query) });
});

// Vulnerability 2: Path Traversal (LFI/Arbitrary File Read)
app.get('/download', (req, res) => {
    let filename = req.query.file;
    
    // [DATA FLOW] Source -> filename -> filePath
    let filePath = path.join(__dirname, 'uploads', path.basename(filename));
    if (!filePath.startsWith(path.join(__dirname, 'uploads'))) {
        return res.status(403).send('Forbidden');
    }
    
    // SINK
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send("Error reading file");
        } else {
            res.send(data);
        }
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
