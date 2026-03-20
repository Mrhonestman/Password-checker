# Password Strength Checker

A cybersecurity tool that analyzes password strength in real time.
Built with Python Flask backend and a cyberpunk-styled HTML frontend.

## Features
- Shannon entropy calculation
- Brute-force crack time estimation (100B hashes/sec)
- Live security criteria checklist
- Improvement recommendations
- Show / hide password toggle

## Tech Stack
- Python 3
- Flask
- HTML / CSS / JavaScript

## Project Structure
\`\`\`
Password-checker/
├── app.py              # Flask server
├── analyzer.py         # Core Python logic
├── README.md           # This file
├── .gitignore          # Git ignore rules
└── templates/
    └── index.html      # Frontend UI
\`\`\`

## How to Run Locally
\`\`\`bash
git clone https://github.com/Mrhonestman/Password-checker.git
cd Password-checker
pip install flask
python app.py
\`\`\`

## Author
GitHub: https://github.com/Mrhonestman