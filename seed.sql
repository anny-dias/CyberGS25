DROP TABLE IF EXISTS users;
CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  role TEXT CHECK(role IN ('admin','user')) NOT NULL DEFAULT 'user',
  password TEXT
);

INSERT INTO users(username, role, password) VALUES
('alice','admin','admin123'),
('bob','user','bobpwd');
