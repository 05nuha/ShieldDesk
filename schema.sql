DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS requests;
 
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    full_name   TEXT NOT NULL,
    student_id  TEXT NOT NULL,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT
);
 
CREATE TABLE requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    category    TEXT NOT NULL,
    details     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'Open',
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
