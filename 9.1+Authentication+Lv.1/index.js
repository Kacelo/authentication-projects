import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

//
const app = express();
const port = 3000;
// 1. connect to DB

const db = new pg.Client({
  user: "vernon",
  host: "localhost",
  database: "auth",
  password: "admin",
  port: 5432,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/secrets", (req, res) => {
  res.render("secrets.ejs");
});

app.post("/register", async (req, res) => {
  // console.log("passsword: ", password);
  // console.log("username:", username);

  try {
    const password = req.body["password"];
    const username = req.body["username"];
    // check result
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists, try logging in.");
    } else {
      const request = await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *;",
        [username, password]
      );
      res.render("secrets.ejs");
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const email = req.body["username"];
  const password = req.body["password"];

  try {
    const request = await db.query(
      "SELECT * FROM users WHERE email =$1 AND password = $2",
      [email, password]
    );
    if (request.rows.length > 0) {
      console.log(request.rows);
      // get returned password and username;
      const user = request.rows[0].email;
      const userPassword = request.rows[0].password;
      if (password === userPassword) {
        res.render("secrets.ejs");
      } else {
        res.send("User not found");
      }
    } else {
      res.send("You have entered incorrect credentials, please try again");
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
