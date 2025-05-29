# Blockchain-Based Land Registry Verification System for Tanzania

## Overview
This project is a prototype solution for addressing land disputes in Tanzania through a secure land registry system. 
It leverages blockchain technology for immutable record storage and RSA digital signatures for authenticity, 
ensuring transparency and preventing fraud.

## Features
- Secure Registration: Admins can register land records with digital signatures.
- Verification: Verify land ownership using blockchain records.
- Duplicate Prevention: Checks for unique land ownership based on plot number, district, and region.
- User Interface: Styled with Bootstrap, featuring plain text error messages with icons.
- Security: Includes Role-Based Access Control (RBAC), simulated MFA, and audit logging.

## Technologies Used
- Backend: Django (Python)
- Cryptography: `cryptography` library (RSA signatures)
- Frontend: HTML, CSS 
- Database: SQLite (prototype) 
- Tools: Git, Django ORM
