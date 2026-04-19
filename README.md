# Nexus

Self-hosted team messaging platform with file sharing. Zero external dependencies (pure Python 3 backend), deployed behind Apache reverse proxy.

## Features

- **Group-based access control** - full user isolation between groups
- **Project hierarchy** - Group > Project > Messages with attachments
- **Inline file attachments** - drag-drop or click to attach, with image preview and lightbox
- **Markdown messages** - full rendering via marked.js (code blocks, tables, links, etc.)
- **Admin bulletins** - announcements visible to all users
- **Keyword detection** - reminds you to attach files when your message mentions them
- **Email notifications** - Gmail SMTP notifies group members on new messages/bulletins
- **API token auth** - curl/script access via Bearer token or X-Auth-Token header
- **Dark mode** - toggle with localStorage persistence, system preference detection
- **Login rate limiting** - 5 failed attempts = 3-hour lockout
- **Upload progress bar** - 1s delayed display for large file uploads
- **Optimistic UI** - messages appear instantly with send status indicators
- **Infinite scroll** - cursor-based pagination for feeds, offset-based for admin lists
- **OA sync** - auto-sync messages and attachments to local work directories
- **Unicode filename support** - RFC 5987 Content-Disposition for non-ASCII filenames

## Architecture

```
Browser --> Apache (HTTPS/443, Basic Auth)
              |
              +--> Static files (HTML/CSS/JS)
              +--> .htaccess [P] proxy --> localhost:5678 (Python backend)
                                            |
                                            +--> SQLite (nexus.db)
                                            +--> uploads/ (files on disk)
```

## Deployment

### Prerequisites

- Apache with `mod_rewrite`, `mod_proxy_http` enabled
- Python 3.6+
- A web-accessible directory with `.htaccess` support (`AllowOverride FileInfo`)
- (Optional) Gmail App Password for email notifications

### Setup

1. Clone to your server's web directory
2. Create `backend/.env` for SMTP (optional):
   ```
   NEXUS_SMTP_HOST=smtp.gmail.com
   NEXUS_SMTP_PORT=587
   NEXUS_SMTP_USER=your@gmail.com
   NEXUS_SMTP_PASS=your-app-password
   NEXUS_SMTP_FROM=your@gmail.com
   ```
3. Start the backend:
   ```bash
   cd backend
   chmod +x start_tencent.sh stop.sh
   ./start_tencent.sh
   # First run will prompt for admin password
   ```
4. Access via `https://your-server/path/to/nexus/index.html`

## API

All endpoints under `/api/`. Auth via session cookie, `Authorization: Bearer <token>`, or `X-Auth-Token: <token>` header.

```bash
# Send message with attachment
curl -X POST -H "Authorization: Bearer TOKEN" \
     -F "content=Here is the report" \
     -F "group_id=1" -F "project_id=1" \
     -F "file=@report.pdf" \
     https://your-server/path/nexus/api/messages

# Text-only message
curl -X POST -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"content":"hello","group_id":1,"project_id":1}' \
     https://your-server/path/nexus/api/messages

# Download file
curl -H "Authorization: Bearer TOKEN" \
     https://your-server/path/nexus/api/files/1/download -O

# List projects
curl -H "Authorization: Bearer TOKEN" \
     https://your-server/path/nexus/api/projects?group_id=1
```

## OA Sync

Automatically sync messages and attachments to local work directories.

Admin sets a `work_dir` for each project (e.g., `fuxiCFD`). When a message is posted, `sync_oa.py` downloads it to `<work_dir>/OA/<yyyymmddHHMM>/msg.md` with YAML frontmatter + attachments.

```bash
# Manual sync
./sync_oa.py

# Hourly cron (set NEXUS_TOKEN and HTACCESS_PASS as env vars)
0 * * * * /path/to/sync_nexus.sh >> sync_oa.log 2>&1
```

## Tech Stack

- **Backend**: Python 3 `http.server` (no framework, no pip dependencies)
- **Database**: SQLite with WAL mode
- **Frontend**: Vanilla JS (ES5), marked.js for Markdown, CSS variables for theming
- **Auth**: HMAC-signed session tokens + API tokens
