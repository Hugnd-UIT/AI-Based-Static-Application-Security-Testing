exports.find = async (query) => {
    // NoSQL Injection [CWE-943]
    return { data: `Searched for ${query}` };
};
