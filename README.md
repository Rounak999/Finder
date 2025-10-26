# 🚩 Capture The Flag (CTF) Challenge

Welcome to an exciting CTF challenge based on a FLASK! 🐍 Your objective is to locate the hidden flag within the system. 🏴 This CTF will test you code review skills and aslo the explotation skills for SQL injection and SSRF. 

## 📍 Flag Location

The flag can be found once you login as admin and by calling a specific endpoint


🔍 Good luck and happy hacking! 🎯

### Note
Try to flag from non localhost IP. 

### Getting Started

1. **Run the Docker Commands:**
   ```bash
   docker pull xploiterd/finder
   docker run -d -p 5000:5000 --name finder xploiterd/finder:latest

