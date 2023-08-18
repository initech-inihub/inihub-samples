const express = require("express");
const app = express();
const { resolve } = require("path");
const got = require("got");
const port = 8080;

app.get("/", (req, res) => {
    const path = resolve("./client/index.html");
    res.sendFile(path);
});

app.listen(port, () => {
    console.log(`INIHuB Sample-App listening on port ${port}`);
});
