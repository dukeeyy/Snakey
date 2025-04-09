# Snakey – Developer Notes

##  Commit Date: [2025-04-09]  
##  Author: Martim Lourenço Silva Rebelo  
##  Commit Type: Feature & Logging Overhaul  

---

### [1] Persistent Daemon Mode
- Refactored Snakey to run **indefinitely** in the background.
- Introduced a safe termination mechanism using a flag file:
  - To stop execution, user must create a `stop_snakey.txt` file.
  - Snakey checks for the file every cycle and exits by itself.
  - The stop file is automatically deleted after shutdown to clean the environment.

---

###  [2] Geolocation-Based Alert System
- Integrated **IP-based geolocation** using:
  - Public IP fetched from `https://api.ipify.org`
  - Country & city resolved using `http://ip-api.com/json/{IP}`
- Configurable list of **known safe countries**:
  ```python
  known_countries = ["Portugal", "Spain"] - can be set to whatever countries are decided
