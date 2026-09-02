# AccessGuard

AccessGuard is a standalone Role-Based Access Control management prototype. It uses HTML5, Tailwind CSS, CSS3, vanilla JavaScript, and LocalStorage. No PHP, XAMPP, MySQL, Node.js server, or installation step is required.

## Run

Open [index.html](index.html) directly in a modern browser. The application seeds realistic demo data into LocalStorage on its first load and retains changes after refresh.

## Demo accounts

| Role | Username | Password |
| --- | --- | --- |
| Admin | `admin` | `admin123` |
| Staff | `staff` | `staff123` |
| User | `user` | `user123` |

Each account is redirected to its matching role workspace and cannot navigate directly to another role workspace.

## Included functionality

- Security intro motion sequence and responsive landing page
- LocalStorage authentication, role detection, session persistence, and logout
- Protected Admin, Staff, and User dashboards
- Permission-aware record management with create, search, sort, edit, and delete controls
- Administrator user management, role configuration, activity monitoring, notifications, and profile editing
- Reusable toast, modal, empty-state, access-restriction, and responsive sidebar components

## Prototype note

LocalStorage authentication and permission checks are appropriate for a front-end demonstration only. A production system must enforce authorization on a trusted backend and must not store passwords in browser storage.