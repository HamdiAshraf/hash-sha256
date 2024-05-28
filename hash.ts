import * as crypto from "crypto";

function generateSalt(length: number): string {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}


function hash(password: string, salt: string): string {
    const combinedString = password + salt;
    return salt + crypto.createHash('sha256').update(combinedString).digest('hex');
}

function compare(password: string, storedHashedPassword: string): boolean {
    const saltLength = 16;
    const salt = storedHashedPassword.slice(0, saltLength);
    const hashedPassword = hash(password, salt);
    return storedHashedPassword === hashedPassword;
}


const plainPassword = 'hamdi123';


const salt = generateSalt(16);
const storedHashedPassword = hash(plainPassword, salt);

console.log(`Stored Hashed Password: ${storedHashedPassword}`);


const passwordsMatch = compare(plainPassword, storedHashedPassword);

console.log(`Passwords Match: ${passwordsMatch}`)