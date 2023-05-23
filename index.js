import bcrypt from "bcrypt";
import express from "express";
const app = express();
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import session from "express-session";
const db = await open({
    driver: sqlite3.Database,
    filename: "database.sqlite"
})

app.use(session({
    secret: "some secret",
    cookie: { maxAge: 86400 },
    saveUninitialized: true,
    resave: false
}));

function auth(req, res, next) {
    if (!req.session.username) {
        res.redirect('/signin');
        return;
    }
    next();
}

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
//Main Page
app.get('/', (req, res) => {
    res.render('index');
});
//sign up
app.get('/signup', (req, res) => {
    res.render('signup', { error: "" });
});
app.post('/signup', async (req, res) => {
    const data = req.body;
    if (await checkUserExistens(data)) {
        res.render('signup', { error: "Username already exists" })
        return;
    }
    const hash = await bcrypt.hash(data.password, 10);
    await db.run("INSERT INTO users (username, password) VALUES (?,?)", data.username, hash);
    res.redirect('/signin');
});

//sign in
app.get('/signin', (req, res) => {
    res.render('signin', { username: "", error: "" });
});
app.post('/signin', async (req, res) => {
    const data = req.body;
    if (!(await checkUserData(data))) {
        res.render('signin', { username: data.username, error: "Username or Password is wrong" });
        return;
    }
    req.session.regenerate(() => {
        req.session.username = data.username;
        req.session.save(() => { res.redirect('/app'); });
    });
});

//the to-do-list 
app.get('/app', auth, async (req, res) => {
    const todos = await db.all("SELECT title, description, time FROM todos WHERE username = ? ORDER BY time DESC", req.session.username);
    res.render('app', { todos: todos });
});
app.post('/app', auth, async (req, res) => {
    const data = req.body;
    await db.run('INSERT INTO todos (title, description, time, username) VALUES (?,?,?,?)', data.title, data.description, new Date(), req.session.username);
    res.redirect('/app');
});

app.listen('3000');

async function checkUserExistens(data) {
    const userdata = await db.get("SELECT username FROM users WHERE username = ?", data.username)
    if (!userdata) {
        return false;
    }
    return true;
}

async function checkUserData(data) {
    const userdata = await db.get("SELECT username, password FROM users WHERE username = ?", data.username);
    if (!userdata) {
        return false;
    }
    return await bcrypt.compare(data.password, userdata.password);
}