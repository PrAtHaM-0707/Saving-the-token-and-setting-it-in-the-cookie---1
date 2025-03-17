const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Hardcoded credentials (in production, these should be environment variables)
const jwtSecret = 'mySuperSecretKey123'; // JWT signing secret
const encryptionKey = Buffer.from('a1b2c3d4e5f6g7h8', 'utf8'); // 16-byte key for AES-128-CBC
const algorithm = 'aes-128-cbc';

const encrypt = (payload) => {
  // Convert payload to JSON string
  const payloadString = JSON.stringify(payload);

  // Encrypt the payload with AES-128-CBC
  const iv = crypto.randomBytes(16); // Random initialization vector
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encrypted = cipher.update(payloadString, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Create JWT with encrypted data and IV
  const tokenPayload = {
    encryptedData: encrypted,
    iv: iv.toString('hex')
  };
  return jwt.sign(tokenPayload, jwtSecret, { expiresIn: '1h' });
};

const decrypt = (token) => {
  try {
    // Verify and decode the JWT
    const decoded = jwt.verify(token, jwtSecret);

    // Extract encrypted data and IV
    const { encryptedData, iv } = decoded;
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Parse and return the decrypted payload
    const result = JSON.parse(decrypted);
    console.log('Success'); // Required by lab
    return result;
  } catch (error) {
    throw new Error('Invalid token or decryption failed');
  }
};

// Self-contained test code (can be left in or removed for submission)
const testPayload = { user: 'john_doe', id: 456 };
const token = encrypt(testPayload);
console.log('Encrypted JWT Token:', token);
try {
  const decryptedPayload = decrypt(token);
  console.log('Decrypted Payload:', decryptedPayload);
} catch (error) {
  console.error('Error:', error.message);
}

module.exports = {
  encrypt,
  decrypt
};