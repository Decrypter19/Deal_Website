# DEAL website + member portal

The public DEAL site and the member portal, served by one small Node.js server
with a SQLite database. Member accounts, tasks, messages, and announcements are
stored on the server — nothing important lives in the browser anymore.

## Run it locally

1. Install Node.js 18 or newer (https://nodejs.org).
2. In this folder:

   ```bash
   npm install
   npm start
   ```

3. Open http://localhost:3000. The portal is at http://localhost:3000/#/portal.

The database is created automatically at `data/deal.sqlite` on first run.
Back up that one file and you have backed up everything.

## First account = officer

The **first person to create an account becomes an officer**. Officers can:

- assign tasks to any member and remove any task
- message any member or everyone at once
- promote members to officer, remove accounts
- see recent sign-in history
- generate a password-reset link for a member

Regular members can see tasks, mark their own tasks done, message officers,
post announcements, and manage their own profile/password.

You can also pre-approve officers with `OFFICER_EMAILS` (see below).

## Settings (environment variables)

Copy `.env.example` to get started. All are optional.

| Variable         | Default                                         | Purpose |
| ---------------- | ----------------------------------------------- | ------- |
| `PORT`           | `3000`                                          | Port to listen on |
| `DB_PATH`        | `./data/deal.sqlite`                            | SQLite file location |
| `OFFICER_EMAILS` | *(empty)*                                       | Comma-separated emails that get the officer role at sign-up |
| `SCHOOL_DOMAINS` | `brophybroncos.org,xaviersaints.org,.edu,k12.` | Email must match one of these to register |

## Password resets

No email service is connected, so "Forgot password" does not send mail.
Instead an officer opens **Members → Reset link** next to the member, and sends
them the link (text, Discord, etc.). The link works once and expires in 2 hours.

## Deploying (free tier friendly)

Any host that runs Node works. Two notes:

- SQLite is a file, so the host needs a **persistent disk** (Render disks,
  Railway volumes, Fly volumes). Point `DB_PATH` at it. Without one the
  database resets on every deploy.
- Cookies are marked `Secure` automatically when `NODE_ENV=production`, so
  serve over HTTPS (every host above does this for you).

A `Dockerfile` is included; it stores the database in `/data`.

## Security notes

- Passwords are hashed with bcrypt; plaintext passwords are never stored or logged.
- Sessions are HTTP-only cookies that expire after 30 days.
- Failed and successful sign-ins are recorded (officers can view them).

## API (for reference)

All routes are under `/api`, JSON in/out, cookie authenticated.

```
POST  /auth/register  /auth/login  /auth/logout  /auth/forgot  /auth/reset
GET   /auth/me        PATCH /auth/me       POST /auth/change-password
GET   /members        GET /members/logins*  PATCH|DELETE /members/:id*  POST /members/:id/reset-link*
GET   /tasks?scope=me|all   POST /tasks   PATCH /tasks/:id   DELETE /tasks/:id
GET   /messages       POST /messages     POST /messages/:id/read
GET   /announcements  POST /announcements  DELETE /announcements/:id
```
`*` = officers only.
