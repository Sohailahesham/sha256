"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
function generateSalt(length) {
    return crypto_1.default.randomBytes(length).toString("hex");
}
function hash(password, salt) {
    const hash = crypto_1.default.createHash('sha256');
    hash.update(password + salt);
    const hashedPass = hash.digest('hex');
    return `${salt}:${hashedPass}`;
}
function compare(password, hashed) {
    const [salt, pass] = hashed.split(':');
    const inputHash = hash(password, salt);
    return inputHash === hashed;
}
const password = "Sohaila";
const salt = generateSalt(16);
const hashedPass = hash(password, salt);
console.log(hashedPass);
console.log("passwords is ", compare("Samer", hashedPass));
console.log("passwords is ", compare("Sohaila", hashedPass));
