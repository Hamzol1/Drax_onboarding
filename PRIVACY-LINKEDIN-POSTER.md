# LinkedIn Poster — Privacy Policy

**Drax Security** · Effective date: **17 June 2026** · Application: **LinkedIn Poster** (Windows desktop)

This Privacy Policy describes how **Drax Security** (“we”, “us”, “our”) handles information when you use the **LinkedIn Poster** desktop application (“App”). The App helps you compose, schedule, and publish content to LinkedIn using LinkedIn’s official APIs after you authorize access.

By installing or using the App, you agree to this Privacy Policy. If you do not agree, do not use the App.

## 1. Who we are

| | |
|---|---|
| **Data controller** | Drax Security |
| **LinkedIn Company Page** | Drax Security |
| **Privacy contact** | [privacy@drax.solutions](mailto:privacy@drax.solutions) |
| **Security contact** | [security@drax-security.com](mailto:security@drax-security.com) |

## 2. Summary

- The App is **local-first**: posts, drafts, media, and credentials stay on **your Windows PC**.
- We do **not** operate a Drax-hosted backend that receives your LinkedIn content or tokens.
- The App talks to **LinkedIn** (and optionally **GitHub** for updates / FFmpeg bootstrap) only to perform actions you request.
- We do **not** sell your personal information.

## 3. Information we process

| Category | Examples | Where stored | Purpose |
|----------|----------|--------------|---------|
| LinkedIn OAuth tokens | Access token, refresh token, expiry, scopes | Local SQLite, encrypted with Windows DPAPI | Authenticate LinkedIn API calls |
| Developer credentials | Client ID, Client Secret you enter | Local `vault.json`, DPAPI-encrypted | Complete OAuth with your LinkedIn app |
| Account profile data | Member URN, display name, org pages, scopes | Local SQLite | Author selection & permission checks |
| Content you create | Post text, mentions, polls, schedules, drafts | Local SQLite | Compose, preview, schedule, publish |
| Media | Images, videos, documents, alt text, thumbnails | `%LOCALAPPDATA%\LinkedInPoster\media` | Attach & upload when you publish |
| Logs | Startup traces, errors, crash diagnostics | `%LOCALAPPDATA%\LinkedInPoster\logs` | Troubleshooting on your device |
| API audit metadata | URLs, HTTP status, timestamps, quota | Local SQLite | Rate-limit awareness |
| App preferences | Timezone, onboarding state, UI settings | Local SQLite | Remember configuration |

## 4. Third parties

### 4.1 LinkedIn (required)

When you connect or publish, the App sends data to LinkedIn APIs (OAuth, posts, media, profile/org lookups). LinkedIn’s processing is governed by [LinkedIn’s Privacy Policy](https://www.linkedin.com/legal/privacy-policy) and [API Terms of Use](https://www.linkedin.com/legal/l/api-terms-of-use).

Authorized scopes may include `openid`, `profile`, `email`, `w_member_social`, and optionally `w_organization_social`.

### 4.2 GitHub (optional)

- **Update checks:** GitHub Releases API only — no post content or tokens sent.
- **FFmpeg bootstrap:** May download FFmpeg from a public GitHub release for local video thumbnails. Media is not uploaded to GitHub.

### 4.3 No Drax cloud collection

The App does **not** send LinkedIn tokens, post bodies, or media to Drax Security servers. No advertising or cross-app tracking.

## 5. Security

- Data directory: `%LOCALAPPDATA%\LinkedInPoster\`
- Sensitive values protected with **Windows DPAPI** (your Windows user profile).
- OAuth uses loopback `http://127.0.0.1` on your machine only.
- You are responsible for securing your Windows account and device.

## 6. Retention & your choices

Data remains until you delete it or uninstall. In the App you can:

- Disconnect LinkedIn accounts (Settings)
- Delete posts/drafts (Posts view)
- Export/import backups (Settings)
- Wipe all local data (Settings)
- Uninstall and delete `%LOCALAPPDATA%\LinkedInPoster\`

Contact [privacy@drax.solutions](mailto:privacy@drax.solutions) for privacy requests.

## 7. Children

Not directed to children under 16. We do not knowingly collect data from children.

## 8. Changes

We may update this policy. The effective date above will change. Continued use after updates constitutes acceptance.

## 9. Contact

**Drax Security — Privacy**  
Email: [privacy@drax.solutions](mailto:privacy@drax.solutions)  
Security: [security@drax-security.com](mailto:security@drax-security.com)

---

© 2026 Drax Security · [HTML version](https://hamzol1.github.io/Drax_onboarding/linkedin-poster/privacy-policy.html) · [Source repository](https://github.com/Hamzol1/Drax_onboarding)
