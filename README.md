# Secure Election System 🗳️🔐

A Java-based secure voting system using RSA encryption and socket programming, developed for CS5780 (Advanced Information Security) at Cal State LA.

## 🔐 Features
- RSA-encrypted communication between:
  - Voter ↔ CLA (Central Legislative Authority)
  - Voter ↔ CTF (Central Tallying Facility)
- Validation number encryption with public keys
- Custom SSL-like handshake for vote authentication
- Secure vote tallying and result display

## 📁 Components
- `CLA.java`: Handles voter registration and validation number generation
- `CTF.java`: Stores encrypted votes and tallies final results
- `Voter.java`: Casts vote and retrieves results securely
- `RSAKeyGenerator.java`: Generates public-private key pairs

## ⚙️ Run Instructions
Compile and run each component separately using:
```bash
javac *.java
java CLA
java CTF
java Voter
