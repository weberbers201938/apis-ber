const appstate = require("./fca/orion/fca-project-orion");
const fs = require("fs");
const cheerio = require('cheerio');
const port = 3000;
const cors = require("cors");
const express = require("express");
const app = express();
const axios = require("axios");
const Multer = require("multer");
const uuid = require("uuid");
const { v4: uuidv4 } = require("uuid");
const moment = require("moment-timezone");
const time = moment.tz("Asia/Manila").format("DD/MM/YYYY || HH:mm:s");
const dl = require("@xaviabot/fb-downloader");
const api_url = "https://b-api.facebook.com/method/auth.login";
const request = require("request");
const ytdl = require("ytdl-core");
const bodyParser = require("body-parser");
const path = require('path');

function generateRandomString(length) {
  let randomString = "";
  while (randomString.length < length) {
    const uuidPart = uuid.v4().replace(/-/g, "");
    randomString += uuidPart;
  }
  return randomString.substr(0, length);
}

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const total = new Map();

console.log("/totals (totals of share)")
app.get('/totals', (req, res) => {
  const data = Array.from(total.values()).map((link, index)  => ({
    session: index + 1,
    url: link.url,
    count: link.count,
    id: link.id,
    target: link.target,
  }));
  res.json(JSON.parse(JSON.stringify(data || [], null, 2)));
});

console.log("/share/submit?cookie=&url=&amount=&interval=")
app.post('/share/submit', async (req, res) => {
  const {
    cookie,
    url,
    amount,
    interval,
  } = req.body;
  if (!cookie || !url || !amount || !interval) return res.status(400).json({
    error: 'Missing state, url, amount, or interval'
  });
  try {
    const cookies = await convertCookie(cookie);
    if (!cookies) {
      return res.status(400).json({
        status: 500,
        error: 'Invalid cookies'
      });
    };
    await share(cookies, url, amount, interval)
    res.status(200).json({
      status: 200
    });
  } catch (err) {
    return res.status(500).json({
      status: 500,
      error: err.message || err
    });
  }
});

async function share(cookies, url, amount, interval) {
  const id = await getPostID(url);
  const accessToken = await getAccessToken(cookies);
  if (!id) {
    throw new Error("Unable to get link id: invalid URL, it's either a private post or visible to friends only");
  }
  const postId = total.has(id) ? id + 1 : id;
  total.set(postId, {
    url,
    id,
    count: 0,
    target: amount,
  });
  const headers = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate',
    'connection': 'keep-alive',
    'content-length': '0',
    'cookie': cookies,
    'host': 'graph.facebook.com'
  };
  let sharedCount = 0;
  let timer;
  async function sharePost() {
    try {
      const response = await axios.post(`https://graph.facebook.com/me/feed?link=https://m.facebook.com/${id}&published=0&access_token=${accessToken}`, {}, {
        headers
      });
      if (response.status !== 200) {
      } else {
        total.set(postId, {
          ...total.get(postId),
          count: total.get(postId).count + 1,
        });
        sharedCount++;
      }
      if (sharedCount === amount) {
        clearInterval(timer);
      }
    } catch (error) {
      clearInterval(timer);
      total.delete(postId);
    }
  }
  timer = setInterval(sharePost, interval * 1000);
  setTimeout(() => {
    clearInterval(timer);
    total.delete(postId);
  }, amount * interval * 1000);
}
async function getPostID(url) {
  try {
    const response = await axios.post('https://id.traodoisub.com/api.php', `link=${encodeURIComponent(url)}`, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data.id;
  } catch (error) {
    return;
  }
}
async function getAccessToken(cookie) {
  try {
    const headers = {
      'authority': 'business.facebook.com',
      'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
      'cache-control': 'max-age=0',
      'cookie': cookie,
      'referer': 'https://www.facebook.com/',
      'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Linux"',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'same-origin',
      'sec-fetch-user': '?1',
      'upgrade-insecure-requests': '1',
    };
    const response = await axios.get('https://business.facebook.com/content_management', {
      headers
    });
    const token = response.data.match(/"accessToken":\s*"([^"]+)"/);
    if (token && token[1]) {
      const accessToken = token[1];
      return accessToken;
    }
  } catch (error) {
    return;
  }
}
async function convertCookie(cookie) {
  return new Promise((resolve, reject) => {
    try {
      const cookies = JSON.parse(cookie);
      const sbCookie = cookies.find(cookies => cookies.key === "sb");
      if (!sbCookie) {
        reject("Detect invalid appstate please provide a valid appstate");
      }
      const sbValue = sbCookie.value;
      const data = `sb=${sbValue}; ${cookies.slice(1).map(cookies => `${cookies.key}=${cookies.value}`).join('; ')}`;
      resolve(data);
    } catch (error) {
      reject("Error processing appstate please provide a valid appstate");
    }
  });
}

console.log("/share?link=&token=&amount=&speed=")
app.post("/share", async (req, res) => {
  const link = req.query.link;
  const token = req.query.token;
  const amounts = req.query.amount;
  const speed = req.query.speed;

  if (!link || !token || !amounts || !speed) {
    return res.status(400).json({
      error: "🔴 Missing input!, Link, token, amount, and speed are required!!",
    });
  }

  const shareCount = amounts;
  const timeInterval = speed;
  const deleteAfter = 60 * 60;

  let sharedCount = 0;
  let timer = null;

  try {
    const a = await axios.get(
      `https://graph.facebook.com/me?access_token=${token}`,
    );
    if (a.data.error) {
      return res.status(401).json({ error: "Invalid access token" });
    }
  } catch (error) {
    return res.status(401).json({ error: "Invalid access token" });
  }
  async function sharePost() {
    try {
      const response = await axios.post(
        `https://graph.facebook.com/me/feed?access_token=${token}&fields=id&limit=1&published=0`,
        {
          link: link,
          privacy: { value: "SELF" },
          no_story: true,
        },
        {
          muteHttpExceptions: true,
          headers: {
            authority: "graph.facebook.com",
            "cache-control": "max-age=0",
            "sec-ch-ua-mobile": "?0",
            "user-agent":
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36",
          },
          method: "post",
        },
      );

      sharedCount++;
      const postIdd = response?.data?.id;

      if (sharedCount === amounts) {
        clearInterval(timer);
        console.log("Finished sharing posts.");

        if (postIdd) {
          setTimeout(() => {
            deletePost(postIdd);
          }, deleteAfter * 1000);
        }
      }
    } catch (error) {
      console.error(`Failed to share post because ${error.response.data}`);
    }
  }

  async function deletePost(postIdd) {
    try {
      await axios.delete(
        `https://graph.facebook.com/${postIdd}?access_token=${token}`,
      );
      console.log(`Post deleted: ${postIdd}`);
    } catch (error) {
      console.error("Failed to delete post:", error.response.data);
    }
  }

  timer = setInterval(sharePost, timeInterval);

  setTimeout(() => {
    clearInterval(timer);
    console.log("Loop stopped.");
  }, shareCount * timeInterval);
  res.json({
    text: `Post share success here\'s some info of your shareboost: Speed of Sharing: ${speed}\n\nAmount: ${amount}\n\nFb-post-link: ${link}\n\nDate and Time of Sharing: ${time}`,
  });
});

const addedLinks = [
  "https://vt.tiktok.com/ZSFPnnywU/",
  "https://vt.tiktok.com/ZSFPWRm3q/",
  "https://vt.tiktok.com/ZSFPW14t4/",
  "https://vt.tiktok.com/ZSFPWFWAC/",
  "https://vt.tiktok.com/ZSFPngg1K/",
  "https://vt.tiktok.com/ZSFPngro4/",
  "https://vt.tiktok.com/ZSFPW13wB/",
  "https://vt.tiktok.com/ZSFPnvf3J/",
  "https://vt.tiktok.com/ZSFPWLQjF/",
  "https://vt.tiktok.com/ZSFPW8FTy/",
  "https://vt.tiktok.com/ZSFPWNLT2/",
  "https://vt.tiktok.com/ZSFPnpxyq/",
  "https://vt.tiktok.com/ZSFPncoC5/",
  "https://vt.tiktok.com/ZSFPnnpTD/",
  "https://vt.tiktok.com/ZSFPnsdpK/",
  "https://vt.tiktok.com/ZSFPnKno6/",
  "https://vt.tiktok.com/ZSFPWNu53/",
  "https://vt.tiktok.com/ZSFPW8VLF/",
  "https://vt.tiktok.com/ZSFPWeArb/",
  "https://vt.tiktok.com/ZSFPWR6Lx/",
  "https://vt.tiktok.com/ZSFPWRgmJ/",
  "https://vt.tiktok.com/ZSFPnoQdb/",
  "https://vt.tiktok.com/ZSFPncbCP/",
  "https://vt.tiktok.com/ZSFPWFCt7/",
  "https://vt.tiktok.com/ZSFPW8khF/",
  "https://vt.tiktok.com/ZSFPWYrfo/",
  "https://vt.tiktok.com/ZSFPnTnv2/",
  "https://vt.tiktok.com/ZSFPnvuhh/",
  "https://vt.tiktok.com/ZSFPWJHvh/",
  "https://vt.tiktok.com/ZSFPWJDBb/",
  "https://vt.tiktok.com/ZSFPnGUYv/",
  "https://vt.tiktok.com/ZSFPnWVh3/",
  "https://vt.tiktok.com/ZSFPnvS45/",
  "https://vt.tiktok.com/ZSFPWdgWJ/",
  "https://vt.tiktok.com/ZSFPWJdJx/",
  "https://vt.tiktok.com/ZSFPnnkVB/",
  "https://vt.tiktok.com/ZSFPnvgw6/",
  "https://vt.tiktok.com/ZSFPnntdW/",
  "https://vt.tiktok.com/ZSFPnvDJ4/",
  "https://vt.tiktok.com/ZSFPnnTHG/",
  "https://vt.tiktok.com/ZSFPnvTgv/",
  "https://vt.tiktok.com/ZSFPntC9m/",
  "https://vt.tiktok.com/ZSFPW12m4/",
  "https://vt.tiktok.com/ZSFPnEn8Y/",
  "https://vt.tiktok.com/ZSFPn7E27/",
  "https://vt.tiktok.com/ZSFPWdgqA/",
  "https://vt.tiktok.com/ZSFPn3F8C/",
  "https://vt.tiktok.com/ZSFPWekL2/",
  "https://vt.tiktok.com/ZSFPW19xj/",
  "https://vt.tiktok.com/ZSFPWJVu4/",
  "https://vt.tiktok.com/ZSFPWdMpP/",
  "https://vt.tiktok.com/ZSFPWMM8P/",
  "https://vt.tiktok.com/ZSFPWmjcm/",
  "https://vt.tiktok.com/ZSFPWBtrv/",
  "https://vt.tiktok.com/ZSFPWarR4/",
  "https://vt.tiktok.com/ZSFPWYWXs/",
  "https://vt.tiktok.com/ZSFPWjyXe/",
  "https://vt.tiktok.com/ZSFPWUK9a/",
  "https://vt.tiktok.com/ZSFPWf4YF/",
  "https://vt.tiktok.com/ZSFPWQTXt/",
  "https://vt.tiktok.com/ZSFPWPWSp/",
  "https://vt.tiktok.com/ZSFPWfjsk/",
  "https://vt.tiktok.com/ZSFPWSWTX/",
  "https://vt.tiktok.com/ZSFPWjcfW/",
  "https://vt.tiktok.com/ZSFPWQkj7/",
  "https://vt.tiktok.com/ZSFPWksfC/",
  "https://vt.tiktok.com/ZSFPWXyys/",
  "https://vt.tiktok.com/ZSFPWj1Mh/",
  "https://vt.tiktok.com/ZSFPW5yf3/",
  "https://vt.tiktok.com/ZSFPWCTKX/",
  "https://vt.tiktok.com/ZSFPWjJ9g/",
  "https://vt.tiktok.com/ZSFPWmW3y/",
  "https://vt.tiktok.com/ZSFPW9bRm/",
  "https://vt.tiktok.com/ZSFPWXX9U/",
  "https://vt.tiktok.com/ZSFPWQ9jD/",
  "https://vt.tiktok.com/ZSFPWfS7a/",
  "https://vt.tiktok.com/ZSFPWhfnt/",
  "https://vt.tiktok.com/ZSFPW6PBn/",
  "https://vt.tiktok.com/ZSFPW6SUu/",
  "https://vt.tiktok.com/ZSFPWj413/",
  "https://vt.tiktok.com/ZSFPWDUvf/",
  "https://vt.tiktok.com/ZSFPWBM2a/",
  "https://vt.tiktok.com/ZSFPWkWbE/",
  "https://vt.tiktok.com/ZSFPWPvbm/",
  "https://vt.tiktok.com/ZSFPWrXAg/",
  "https://vt.tiktok.com/ZSFPWAp7B/",
];

console.log("/codm (random codm video)")
app.post("/codm", async function (req, res) {
  try {
    const randomCodm = Math.floor(Math.random() * addedLinks.length);
    const response = await axios.get(
      `https://gemini-ai-uk.onrender.com/tikdl?url=${addedLinks[randomCodm]}`,
    );
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

console.log("/addLink (highlights codm video)")
app.post("/addLink", (req, res) => {
  const { link } = req.query;

  if (!link) {
    return res.status(400).json({ error: "Link is required" });
  }

  addedLinks.push(link);

  res.json({ success: true, message: "Link added successfully" });
});

let conf;

function convertTextToDurationObject(text) {
  const parts = text.split(/\s(?=\[\d{2}:\d{2}\.\d{2}\])/);
  const result = {};

  parts.forEach((part) => {
    const [duration, content] = part.split("] ");
    result[duration.slice(1)] = content;
  });

  return result;
}

class Musix {
  constructor() {
    this.tokenUrl =
      "https://apic-desktop.musixmatch.com/ws/1.1/token.get?app_id=web-desktop-app-v1.0";
    this.searchTermUrl =
      "https://apic-desktop.musixmatch.com/ws/1.1/track.search?app_id=web-desktop-app-v1.0&page_size=5&page=1&s_track_rating=desc&quorum_factor=1.0";
    this.lyricsUrl =
      "https://apic-desktop.musixmatch.com/ws/1.1/track.subtitle.get?app_id=web-desktop-app-v1.0&subtitle_format=lrc";
    this.lyricsAlternative =
      "https://apic-desktop.musixmatch.com/ws/1.1/macro.subtitles.get?format=json&namespace=lyrics_richsynched&subtitle_format=mxm&app_id=web-desktop-app-v1.0";
  }

  async get(url) {
    try {
      const response = await axios.get(url, {
        headers: {
          authority: "apic-desktop.musixmatch.com",
          cookie: "AWSELBCORS=0; AWSELB=0;",
        },
      });
      return response.data;
    } catch (error) {
      throw new Error("Failed to fetch data from the API");
    }
  }

  async getToken() {
    try {
      const result = await this.get(this.tokenUrl);
      const token = result.message.body.user_token;
      await this.saveToken(token);
      return token;
    } catch (error) {
      throw new Error("Failed to retrieve access token");
    }
  }

  async saveToken(token) {
    const expiration_time = Date.now() + 600000; // 10 minutes
    const token_data = { user_token: token, expiration_time };
    conf = JSON.stringify(token_data);
    //await fs.writeFile('musix.txt', JSON.stringify(token_data));
  }

  async checkTokenExpire() {
    try {
      const tokenData = await this.loadToken();
      const { expiration_time } = tokenData;
      if (expiration_time < Date.now()) {
        await this.getToken();
      }
    } catch (error) {
      await this.getToken();
    }
  }

  async loadToken() {
    //const tokenData = await fs.readFile('musix.txt', 'utf-8');
    return JSON.parse(conf);
  }

  async getLyrics(trackId) {
    try {
      await this.checkTokenExpire();
      const tokenData = await this.loadToken();
      const formattedUrl = `${this.lyricsUrl}&track_id=${trackId}&usertoken=${tokenData.user_token}`;
      const result = await this.get(formattedUrl);
      let lyrics = result.message.body.subtitle.subtitle_body;
      let val = convertTextToDurationObject(lyrics);
      return val;
    } catch (error) {
      console.log(error);
      throw new Error("Failed to retrieve lyrics");
    }
  }

  async getLyricsAlternative(title, artist, duration = null) {
    try {
      await this.checkTokenExpire();
      const tokenData = await this.loadToken();
      let formattedUrl = `${this.lyricsAlternative}&usertoken=${tokenData.user_token}&q_album=&q_artist=${artist}&q_artists=&track_spotify_id=&q_track=${title}`;
      if (duration !== null) {
        formattedUrl += `&q_duration=${duration}`;
      }
      const result = await this.get(formattedUrl);
      const lyrics =
        result.message.body.macro_calls["track.subtitles.get"].message.body
          .subtitle_list[0].subtitle.subtitle_body;
      const lrcLyrics = this.getLrcLyrics(lyrics);
      return lrcLyrics;
    } catch (error) {
      throw new Error("Failed to retrieve alternative lyrics");
    }
  }

  async searchTrack(query) {
    try {
      await this.checkTokenExpire();
      const tokenData = await this.loadToken();
      const formattedUrl = `${this.searchTermUrl}&q=${query}&usertoken=${tokenData.user_token}`;
      const result = await this.get(formattedUrl);
      if (!result.message.body.track_list) {
        throw new Error("No track found");
      }
      for (const track of result.message.body.track_list) {
        const trackName = `${track.track.track_name} ${track.track.artist_name}`;
        if (query.includes(trackName)) {
          return track.track.track_id;
        }
      }
      return result.message.body.track_list[0].track.track_id;
    } catch (error) {
      throw new Error("Failed to search track");
    }
  }

  getLrcLyrics(lyrics) {
    let lrc = "";
    if (lyrics) {
      for (const item of lyrics) {
        const { minutes, seconds, hundredths, text } = item.time;
        lrc += `[${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(hundredths).padStart(2, "0")}]${text || "♪"}\n`;
      }
    }
    return lrc;
  }
}

const musix = new Musix();

console.log("/lyrics/musicnamehere")
app.get("/lyrics/:trackId", async (req, res) => {
  try {
    const song = await musix.searchTrack(req.params.trackId);
    const lyrics = await musix.getLyrics(song);
    let cooked = {
      code: 200,
      message: "success",
      lyrics,
    };
    res.type("json").send(JSON.stringify(cooked, null, 2) + "\n");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

const tiktok = require("./tiktokdl.js");

console.log("/tikdl?url=")
app.get("/tikdl", async (req, res) => {
  if (!!req.query.url) {
    let data = await tiktok.getVideoInfo(req.query.url);
    res.type("json").send(JSON.stringify(data, null, 2) + "\n");
  } else {
    res
      .type("json")
      .send(JSON.stringify({ message: "Please input url." }, null, 2) + "\n");
  }
});

const { GoogleGenerativeAI } = require("@google/generative-ai");
console.log("/gemini?prompt=&apikey=")
app.get("/gemini", async (req, res) => {
  const prompt = req.query.prompt;
  const apikey = req.query.apikey;
  // Access your API key as an environment variable (see "Set up your API key" above)
  const genAI = new GoogleGenerativeAI(apikey);

  async function run() {
    try {
      const generationConfig = {
        stopSequences: ["red"],
        maxOutputTokens: 1024,
        temperature: 1,
        topP: 1,
        topK: 40,
      };
      // For text-only input, use the gemini-pro model
      const model = genAI.getGenerativeModel({
        model: "gemini-pro",
        generationConfig,
      });

      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();
      console.log(text);
      res.json({ success: text });
    } catch (e) {
      console.log(e);
      res.json({ error: e.message });
    }
  }
  run(prompt);
});

console.log("/eaaaay/api?user=&pass=")
app.get("/eaaaay/api", (req, res) => {
  const user = req.query.user;
  const pass = req.query.pass;
  const nigga = "6628568379|c1e620fa708a1d5696fb991c1bde5662";
  if (!user || !pass) {
    return res.send({ message: "Both username and password are required" });
  }

  const params = {
    format: "json",
    device_id: "yrcyg4m1-o7m5-pghw-atiu-n04mh4nlka6n",
    email: user,
    password: pass,
    locale: "en_US",
    method: "auth.login",
    access_token: nigga,
  };

  request.get({ url: api_url, qs: params }, (error, response, body) => {
    if (error) {
      return res.send({ message: "Internal server error" });
    }
    const resJson = JSON.parse(body);

    if (resJson.access_token) {
      return res.send({ eaaaay_token: resJson.access_token });
    } else {
      return res.send({ message: "Wrong Credentials" });
    }
  });
});

console.log("/ainz/api?username=&password=")
app.get("/ainz/api", (req, res) => {
  const access_token = "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32";
  const username = req.query.username;
  const password = req.query.password;

  if (!username || !password) {
    return res.send({ message: "Both username and password are required" });
  }

  const params = {
    format: "json",
    generate_session_cookies: "1",
    generate_machine_id: "1",
    generate_analytics_claim: "1",
    device_id: "yrcyg4m1-o7m5-pghw-atiu-n04mh4nlka6n",
    email: username,
    password: password,
    locale: "en_US",
    client_country_code: "US",
    credentials_type: "device_based_login_password",
    fb_api_caller_class: "com.facebook.account.login.protocol.Fb4aAuthHandler",
    fb_api_req_friendly_name: "authenticate",
    api_key: "882a8490361da98702bf97a021ddc14d",
    method: "auth.login",
    access_token: access_token,
  };

  request.get({ url: api_url, qs: params }, (error, response, body) => {
    if (error) {
      return res.send({ message: "Internal server error" });
    }

    const responseJson = JSON.parse(body);

    if (responseJson) {
      return res.send({
        access_token: responseJson.access_token,
        session_cookies: responseJson.session_cookies,
      });
    } else {
      return res.send({ message: "Wrong Credentials" });
    }
  });
});

console.log("/gen")
app.get("/gen", async (req, res) => {
  try {
    const response = await axios.get(
      "https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1",
    );
    const getemail = response.data[0];
    res.json({ email: getemail });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Err: 500" });
  }
});

console.log("/inbox/emailhere")
app.get("/inbox/:email", async (req, res) => {
  try {
    const divide = req.params.email.split("@");
    const name = divide[0];
    const domain = divide[1];
    const response = await axios.get(
      `https://www.1secmail.com/api/v1/?action=getMessages&login=${name}&domain=${domain}`,
    );
    const messages = response.data;
    const tite = [];
    for (const message of messages) {
      const msgId = message.id;
      const sendmsg = await axios.get(
        `https://www.1secmail.com/api/v1/?action=readMessage&login=${name}&domain=${domain}&id=${msgId}`,
      );
      const sendmessage = {
        from: sendmsg.data.from,
        subject: sendmsg.data.subject,
        body: sendmsg.data.textBody,
        date: sendmsg.data.date,
      };
      tite.push(sendmessage);
    }
    res.json(tite);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Err: 500" });
  }
});

console.log("/fbdl?url=")
app.get("/fbdl", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.json({ result: "missing url nigga " });
  try {
    const result = await dl(url);
    const videoData = await result.sd;
    res.json({ result: videoData });
  } catch (e) {
    res.json({ error: e.message });
  }
});

console.log("/ytdl?url=")
app.get("/ytdl", async (req, res) => {
  try {
    const { url } = req.query;

    if (!url || !ytdl.validateURL(url)) {
      return res.status(400).json({ error: "Invalid YouTube URL" });
    }

    const info = await ytdl.getInfo(url);
    const videoFormat = ytdl.chooseFormat(info.formats, { quality: "lowest" });

    if (!videoFormat) {
      return res
        .status(400)
        .json({ error: "No video format available for the provided URL" });
    }

    res.redirect(videoFormat.url);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: "An error occurred" });
  }
});


async function qt(page, search) {
  try {
    
    const url = `https://pinayflix.me/page/${page}/?s=${search}`;
    const res = await axios.get(url);
    const $ = cheerio.load(res.data);

    const data = [];

    const promises = [];

    $('#primary').find('a').each((i, element) => {
      const val = $(element).attr('href');

      if (val && val.startsWith('http')) {
        promises.push(
          axios.get(val).then((scr) => {
            const links = cheerio.load(scr.data);

            const title = links('title').text();
            const img = links('meta[property="og:image"]').attr('content');
            const embedURL = links('meta[itemprop="contentURL"]').attr('content');

            if (img !== undefined) { 
              data.push({ title, img, link: val, video: embedURL });
            }
          })
        );
      }
    });

    await Promise.all(promises);
    return data;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

async function gt(search) {
  const url = `https://pinayflix.me/?search=${search}`;
  const res = await axios.get(url);
  const $ = cheerio.load(res.data);

  const data = [];

  const promises = $('#main > div.videos-list').map(async (i, e) => {
    const tu = $(e).find('img');
    const ur = $(e).find('a');

    return Promise.all(
      tu.map(async (rel, val) => {
        const al = $(val).attr('alt');
        const sr = $(val).attr('src');

        if (ur[rel]) {
          const oi = $(ur[rel]).attr('href');

          if (oi) {
            const response = await axios.get(oi);
            const $$ = cheerio.load(response.data);
            const embedURL = $$('meta[itemprop="contentURL"]').attr('content');
            data.push({ title: al, img: sr, link: oi, video: embedURL });
          }
        }
      })
    );
  }).get();

  await Promise.all(promises);
  return data;
}

console.log("/porn?search=&page=")
app.get('/porn', async (req, res) => {
  const search = req.query.search;
  const page = req.query.page;

  if (!search) {
    res.status(400).json({ error: "Invalid parameters" });
  } else {
    try {
      qt(1, search)
      .then((data) => {
        console.log(data);
        const fk = JSON.stringify(data, null, 2);
        res.status(200).set('Content-Type', 'application/json').end(fk);
      })
      .catch((e) => {
        console.log(e);
      });
    
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  } 

  if (page) {
    try {
      qt(page, search)
        .then((data) => {
          console.log(data);
          const fk = JSON.stringify(data, null, 2);
          res.status(200).set('Content-Type', 'application/json').end(fk);
        })
        .catch((e) => {
          console.log(e);
        });
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  };
});

//console.log("/appstate?e=&p=")
//app.get("/appstate", (req, res) => {
//const email = req.query.e;
//const password = req.query.p;
// account information
//appstate({email, password}, (err, api) => {
//  if (err) {
//      res.status(401).send({ error: err.message });
//  } else {
//  try {
//    const randomString = generateRandomString(5);
    //create appstate
//    const result = api.getAppState();
    
//    const results = (JSON.stringify(result, null, 2))
//fs.writeFileSync(`${email}.${randomString}.json`, results)
//    console.log(results)
//      res.type("json").send({ success: results})
     //logging out the account:>
//    api.logout();
//    } catch(e) {
//res.json({ error: e.message })
//  console.log(e)
//      }
//    }
//  })
//});
                        
console.log("/appstate?e=&p=")
app.get("/appstate", async (req, res) => {
  const email = req.query.e;
  const password = req.query.p;
  try {
    const response = await axios.get(`https://m8jpfz-3000.csb.app/appstate?e=${email}&p=${password}`);
    const result = response.data;
    res.json({ result });
    console.log({ result });
  } catch (e) {
    res.json({ error: e.message });
    console.log(e);
  }
});

console.log("/autobot?state=&pref=&uid=&botname=");
app.post("/autobot", async (req, res) => {

const appstates = req.query.state
const input_prefix = req.query.pref;
const input_admin = req.query.uid;
const input_botname = req.query.botname
  //command lists
let cmds = [{
  'commands': [
  "adduser",
  "ai",
  "bal",
  "bes",
  "catgpt",
  "chesca",
  "claire",
  "colorroulette",
  "cyberdetective",
  "dice",
  "dogbot",
  "emojimix",
  "emojiroulette",
  "facebook",
  "fbshare",
  "gemini",
  "gpt",
  "help",
  "horse",
  "llama",
  "music",
  "numberguess",
  "out",
  "ping",
  "pinterest",
  "poli",
  "quiz",
  "rankup",
  "redroom",
  "remini",
  "rps",
  "sendmoney",
  "share",
  "shoti",
  "shoticron",
  "sim",
  "slot",
  "spaceexplorer",
  "sumi",
  "tempmail",
  "tempnumber",
  "tid",
  "trace",
  "uid",
  "uncleroger",
  "unsent",
  "uptime"
  ]
}, {
  'handleEvent': [
  "joinNoti"
  ]
}];
try {
    const state = JSON.parse(appstates);
    if (state && typeof state === 'object') {
const response = await axios.post('https://wl2kpp-26011.csb.app/login', {
         body: JSON.stringify({
         state: state,
         commands: cmds,
         prefix: input_prefix,
         admin: input_admin,
         botName: input_botname
 }),
      headers: {
      'Content-Type': 'application/json',
    }
});
     if (response.data.success === 200) {
        res.json({ result: response.data.message })
        console.log(response.data.message)  
             } else {
              res.json({ result: response.data.message })
              }
         } else {
      res.json({ error: 'Invalid JSON data. Please check your input.' });
    }
        } catch (parseErr) {
           res.json({ error: parseErr.message })
          console.error(parseErr);
        }       
  }); 

      
app.listen(port, () => console.log(`App is listening on port ${port}`));
