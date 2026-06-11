# VulnMart v1.0.0

**An Intentionally Vulnerable Web Application for Web Pentesting Training**

VulnMart is a realistic e-commerce platform built specifically for web application security training. It covers a vast range of web vulnerabilities across multiple difficulty levels.

---

## Test Accounts

| Username | Password | Role |
|---|---|---|
| admin | admin123 | Administrator |
| john_doe | password123 | User |
| alice_smith | password123 | User |
| bob_jones | password123 | User |

---

## Setup

```bash
docker-compose up --build
```

Access at: `http://localhost:8080`

Admin panel: `http://localhost:8080/admin/`

---

## Updating

```bash
git fetch --tags && git checkout v1.0.0   # specific version (or: git pull for latest)
docker-compose up --build
```

If `db/init.sql` changed, reset the database first: `docker-compose down -v`

Check the running version at `http://localhost:8080/version.php` or in the page footer.

---

## Difficulty Control

All vulnerabilities are individually configurable through the admin settings panel at `/admin/settings.php`.

- **Low** — Fully vulnerable
- **Medium** — Partial mitigations applied
- **Hard** — Properly secured

---

## For Educational Use Only

This application is intentionally vulnerable. Never deploy on a public network.

A self-contained lab for practicing and teaching web application penetration testing. Developed by TechSky - Security Research Team.
