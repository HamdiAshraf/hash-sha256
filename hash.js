"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
function generateSalt(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}
function hash(password, salt) {
    var combinedString = password + salt;
    return salt + crypto.createHash('sha256').update(combinedString).digest('hex');
}
function compare(password, storedHashedPassword) {
    var saltLength = 16;
    var salt = storedHashedPassword.slice(0, saltLength);
    var hashedPassword = hash(password, salt);
    return storedHashedPassword === hashedPassword;
}
var plainPassword = 'hamdi123';
// Generate a salt and hash the plain password
var salt = generateSalt(16);
var storedHashedPassword = hash(plainPassword, salt);
console.log("Stored Hashed Password: ".concat(storedHashedPassword));
// Compare the plain password with the stored hashed password
var passwordsMatch = compare(plainPassword, storedHashedPassword);
console.log("Passwords Match: ".concat(passwordsMatch));
