# Sample data

`sample_logs.csv` contains **simulated** authentication records. Everything in it is fictional.

- Event IDs start with `SIM-` so simulated records can always be recognised.
- IP addresses come from ranges reserved for documentation and private networks. They do not belong to real machines.
- Usernames are made up. There are no passwords or secrets.
- Three rows are deliberately broken (bad time, bad IP, unknown status) to demonstrate input validation.
- One IP (`10.0.0.250`) is a harmless backup script that still triggers an alert. This shows that rules can produce false positives.

Simulated data is much cleaner than real logs. Real logs are noisier, bigger and have more edge cases.
