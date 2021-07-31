const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const fetch = require("node-fetch");
require('dotenv').config();
const app = express();

const OAUTH2_ENDPOINT = "https://discord.com/api/oauth2";
const OAUTH2_AUTHORIZATION_ENDPOINT = OAUTH2_ENDPOINT + "/authorize";
const OAUTH2_TOKEN_ENDPOINT = OAUTH2_ENDPOINT + "/token";
const OAUTH2_CURRENT_AUTHORIZATION_ENDPOINT = OAUTH2_ENDPOINT + "/@me";
const { CLIENT_ID, REDIRECT_URI, CLIENT_SECRET, SESSION_SECRET, SERVER_PORT } = process.env;

function build_url(endpoint, parameters) {
  return new URL("?" + new URLSearchParams([...Object.entries(parameters)]).toString(), endpoint).toString();
}
function generate_state() {
  return crypto.randomBytes(32).toString("base64url");
}
app.set("view engine", "ejs");
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  cookie: { sameSite: "lax" },
  saveUninitialized: true
}));

app.get('/', (req, res) => {
  res.send('<a href="/login"> login </a>');
});


app.get('/login', (req, res) => {
  const state = generate_state();
  const url = build_url(OAUTH2_AUTHORIZATION_ENDPOINT, {
    client_id: CLIENT_ID,
    response_type: "code",
    scope: ["identify"].join(" "),
    redirect_uri: REDIRECT_URI,
    //prompt: ["none"].join(" "),
    state,
  });
  req.session.state = state;
  res.redirect(302, url);
});
async function callback_success(req, res) {
  const { state: sessionState } = req.session;
  const { state: queryState, code } = req.query;

  if (queryState == null || code == null) {
    res.status(400).send("insufficient query parameter.");
    return;
  }
  try {
    await new Promise((resolve, reject) => req.session.regenerate((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    }));
  } catch (err) {
    console.error(err);
    res.status(500).send("internal server error!");
    return;
  }
  if (sessionState !== queryState) {
    res.status(400).send("invalid state.");
    return;
  }
  const token_response = await fetch(OAUTH2_TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    })
  });
  if (token_response.status !== 200) {
    res.status(500).send("failed to exchange code.");
    return;
  }
  const { access_token } = await token_response.json();
  const current_authorization = await fetch(OAUTH2_CURRENT_AUTHORIZATION_ENDPOINT, {
    headers: {
      "Authorization": `Bearer ${access_token}`,
    },
  });
  if (current_authorization.status !== 200) {
    res.status(500).send("failed to fetch authorization information.");
    return;
  }
  const { user: { username, discriminator } } = await current_authorization.json();
  const data = {
    username,
    discriminator
  };
  res.render("./authorized.ejs", data);
}
async function callback(req, res) {
  if ("code" in req.query) {
    await callback_success(req, res);
    return;
  }
  if ("error" in req.query) {
    const { error } = req.query;
    res.render("./authorize_error.ejs", { error });
    return;
  }
  return res.status(400).send("invalid request");
}
app.get("/callback", (req, res) => {
  callback(req, res).catch(err => {
    console.error(err);
  });
});
app.listen(SERVER_PORT);