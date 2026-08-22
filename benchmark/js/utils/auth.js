// Hardcoded Secret [CWE-798]
const secret = "SUPER_SECRET_ADMIN_TOKEN_12345";
const admin = "admin";

exports.verify = (u, p) => {
    return u === admin && p === secret;
};
