const express = require('express');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const _ = require('lodash');

const app = express();
const db = new sqlite3.Database('app.db');
const SESSION_SECRET = 'changeme-secret-123';
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)');

app.use(express.json());

app.post('/register', (req, res) => {
  const { name, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  db.run('INSERT INTO users (name, password) VALUES (?, ?)', [name, hash], () => res.sendStatus(201));
});

app.get('/search', (req, res) => {
  db.all(`SELECT id, name FROM users WHERE name = '${req.query.name}'`, (err, rows) => res.json(rows));
});

app.get('/hello', (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'files', req.query.file));
});

app.post('/settings', (req, res) => {
  const settings = _.merge({}, req.body);
  res.json(settings);
});

app.delete('/users/:id', (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], () => res.sendStatus(204));
});

app.listen(3000);
