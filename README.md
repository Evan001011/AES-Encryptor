# AES Encryptor

A simple and secure AES encryption/decryption web app designed primarily for mobile devices but fully functional on desktop browsers as well.

## Features

- Encrypt and decrypt messages using AES with a passphrase derived from your first and last name.
- Uses strong key derivation (PBKDF2 with 250,000 iterations) and HMAC validation for message integrity.
- Friendly UI with a dark theme optimized for mobile screens, but works smoothly on computers too.
- Copy encrypted or decrypted results to clipboard with a single click.
- Loading animation to indicate processing during encryption and decryption.

## How It Works

- The passphrase is generated by concatenating the lowercased first and last names entered.
- AES encryption uses CBC mode with PKCS7 padding.
- Keys and HMAC are derived securely from the passphrase and random salt using PBKDF2.
- The encrypted message includes salt, IV, ciphertext, and HMAC, encoded in base64 and concatenated with colons.
- Decryption verifies the HMAC before decrypting to ensure message authenticity.

## Technologies Used

- [CryptoJS](https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js) (loaded via CDN) for cryptographic operations.
- Vanilla JavaScript for all encryption, decryption, UI interaction, and validation.
- Responsive CSS tailored for mobile-first design with smooth user experience on desktop as well.

## Usage

1. Enter the message to encrypt or decrypt.
2. Enter your First Name and Last Name (only alphabetic characters allowed).
3. Click **Encrypt** to encrypt the message or **Decrypt** to decrypt.
4. The output will be displayed below with an option to copy the result to clipboard.

## Security Notes

- The encryption depends on the correct full name (first + last) as the passphrase.
- Input validation prevents non-alphabetic characters in the name fields.
- HMAC validation protects against tampering or incorrect passphrase.
- Please do **not** use this app for highly sensitive or critical data without additional security considerations.

## Compatibility

- Works on all modern browsers.
- Optimized and styled primarily for mobile screens but fully usable on desktop.

## Credits

- Built using [CryptoJS](https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js) library for AES and HMAC functions.

