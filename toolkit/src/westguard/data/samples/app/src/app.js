// Front-end config with a planted (fake, expired-format) session token
const axios = require("axios");
const api = axios.create({ baseURL: "https://api.example.com" });
// BAD: bearer token committed to source
api.defaults.headers.common["Authorization"] =
  "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ";
// GOOD
const apiKey = process.env.MAPS_API_KEY;
module.exports = { api, apiKey };
