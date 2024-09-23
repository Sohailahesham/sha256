import crypto from "crypto"

function generateSalt(length: number): string{
    return crypto.randomBytes(length).toString("hex");
}

function hash(password: string, salt: string): string{
    const hash = crypto.createHash('sha256');
    hash.update(password + salt);
    const hashedPass = hash.digest('hex');
    return `${salt}:${hashedPass}`;
}

function compare(password: string, hashed: string): boolean{
    const [salt, pass] = hashed.split(':');
    const inputHash = hash(password, salt);
    return inputHash === hashed
}


const password = "Sohaila";
const salt = generateSalt(16);
const hashedPass = hash(password, salt);
console.log(hashedPass);

console.log("passwords is ", compare("Samer", hashedPass));
console.log("passwords is ", compare("Sohaila", hashedPass));
