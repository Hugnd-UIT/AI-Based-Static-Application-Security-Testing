const { MongoClient } = require('mongodb');

const MONGO_URI = 'mongodb://localhost:27017';
const client = new MongoClient(MONGO_URI);

async function getDb() {
    if (!client.topology || !client.topology.isConnected()) {
        await client.connect();
    }
    return client.db('appdb');
}

// NoSQL Injection [CWE-943]
exports.find = async (query) => {
    const db = await getDb();
    const collection = db.collection('users');
    const result = await collection.find({ username: query }).toArray();
    return result;
};

exports.findByFilter = async (filter) => {
    const db = await getDb();
    const collection = db.collection('users');
    const result = await collection.find(filter).toArray();
    return result;
};
