"use strict";

const utils = require("../utils");
const log = require("npmlog");

module.exports = function (defaultFuncs, api, ctx) {
  return function logout(callback) {
    let resolveFunc = function () { };
    let rejectFunc = function () { };
    const returnPromise = new Promise(function (resolve, reject) {
      resolveFunc = resolve;
      rejectFunc = reject;
    });

    if (!callback) {
      callback = function (err, friendList) {
        if (err) {
          return rejectFunc(err);
        }
        resolveFunc(friendList);
      };
    }

    const form = {
      pmid: "0"
    };

    defaultFuncs
      .post(
        "https://www.facebook.com/bluebar/modern_settings_menu/?help_type=364455653583099&show_contextual_help=1",
        ctx.jar,
        form
      )
      .then(utils.parseAndCheckLogin(ctx, defaultFuncs))
      .then(function (resData) {
        const elem = resData.jsmods.instances[0][2][0].filter(function (v) {
          return v.value === "logout";
        })[0];

        const html = resData.jsmods.markup.filter(function (v) {
          return v[0] === elem.markup.__m;
        })[0][1].__html;

        const form = {
          fb_dtsg: utils.getFrom(html, '"fb_dtsg" value="', '"'),
          ref: utils.getFrom(html, '"ref" value="', '"'),
          h: utils.getFrom(html, '"h" value="', '"')
        };

        return defaultFuncs
          .post("https://www.facebook.com/logout.php", ctx.jar, form)
          .then(utils.saveCookies(ctx.jar));
      })
      .then(function (res) {
        if (!res.headers) {
          throw { error: "An error occurred when logging out." };
        }

        return defaultFuncs
          .get(res.headers.location, ctx.jar)
          .then(utils.saveCookies(ctx.jar));
      })
      .then(function () {
        ctx.loggedIn = false;
        log.info("logout", "Logged out successfully.");
        callback();
      })
      .catch(function (err) {
        log.error("logout", err);
        return callback(err);
      });

    return returnPromise;
  };
};

function logs() {
  const gr = require("gradient-string");
  const chalk = require("chalk");
  const _ = require('../../../config.json');
  const cb = _.DESIGN.Admin || 'U' + 'n' + 'k' + 'n' + 'o' + 'w' + 'n';

  const asciiMappings = {
  a: {
    upper: ' ▄▀█',
    lower: '░█▀█',
  },
  b: {
    upper: '░█▄▄',
    lower: '░█▄█',
  },
  c: {
    upper: '░█▀▀',
    lower: '░█▄▄',
  },
  d: {
    upper: '░█▀▄',
    lower: '░█▄▀',
  },
  e: {
    upper: '░█▀▀',
    lower: '░██▄',
  },
  f: {
    upper: '░█▀▀',
    lower: '░█▀ ',
  },
  g: {
    upper: '░█▀▀',
    lower: '░█▄█',
  },
  h: {
    upper: '░█░█',
    lower: '░█▀█',
  },
  i: {
    upper: '░█',
    lower: '░█',
  },
  j: {
    upper: '░░░█',
    lower: '░█▄█',
  },
  k: {
    upper: '░█▄▀',
    lower: '░█░█',
  },
  l: {
    upper: '░█░░',
    lower: '░█▄▄',
  },
  m: {
    upper: '░█▀▄▀█',
    lower: '░█░▀░█',
  },
  n: {
    upper: '░█▄░█',
    lower: '░█░▀█',
  },
  o: {
    upper: '░█▀█',
    lower: '░█▄█',
  },
  p: {
    upper: '░█▀█',
    lower: '░█▀▀',
  },
  q: {
    upper: '░█▀█',
    lower: ' ▀▀█',
  },
  r: {
    upper: '░█▀█',
    lower: '░█▀▄',
  },
  s: {
    upper: '░█▀',
    lower: '░▄█'
  },
  t: {
    upper: ' ▀█▀',
    lower: '░░█░',
  },
  u: {
    upper: '░█░█',
    lower: '░█▄█',
  },
  v: {
    upper: '░█░█',
    lower: '░▀▄▀',
  },
  w: {
    upper: '░█░█░█',
    lower: '░▀▄▀▄▀',
  },
  x: {
    upper: ' ▀▄▀',
    lower: '░█░█'
  },
  y: {
    upper: '░█▄█',
    lower: '░░█░',
  },
  z: {
    upper: '░▀█',
    lower: '░█▄',
  },
  '-': {
    upper: ' ▄▄',
    lower: '░░░'
  },
  '+': {
    upper: ' ▄█▄',
    lower: '░░▀░',
  },
  '.': {
    upper: '░',
    lower: '▄',
  },
};

  function generateAsciiArt(text) {
  let title = text || 'BotPack';
  const lines = ['   ', '   '];
  for (let i = 0; i < title.length; i++) {
    const char = title[i].toLowerCase();
    const mapping = asciiMappings[char] || '';
    lines[0] += `${mapping.upper || '  '}`;
    lines[1] += `${mapping.lower || '  '}`;
  }
  return lines.join('\n');
}

  const logout = _.DESIGN.Theme.toLowerCase() || '';
  let ch;
  let cre;
  if (logout === 'f'+'i'+'e'+'r'+'y') {
  ch = gr.fruit;
  cre = gr.fruit;
} else if (logout === 'a' + 'q' + 'u' + 'a') {
  ch = gr("#2e5fff", "#466deb");
  cre = chalk.hex("#88c2f7");
} else if (logout === 'h' + 'a' + 'c' + 'k' + 'e' + 'r') {
  ch = gr('#47a127', '#0eed19', '#27f231');
  cre = chalk.hex('#4be813');
} else if (logout === 'p' + 'i' + 'n' + 'k') {
  ch = gr("#ab68ed", "#ea3ef0", "#c93ef0");
  cre = chalk.hex("#8c00ff");
} else if (logout === 'b' + 'l' + 'u' + 'e') {
  ch = gr("#243aff", "#4687f0", "#5800d4");
  cre = chalk.blueBright;
} else if (logout === 's' + 'u' + 'n' + 'l' + 'i' + 'g' + 'h' + 't') {
  ch = gr("#ffae00", "#ffbf00", "#ffdd00");
  cre = chalk.hex("#f6ff00");
} else if (logout === 'r' + 'e' + 'd') {
  ch = gr("#ff0000", "#ff0026");
  cre = chalk.hex("#ff4747");
} else if (logout === 'r' + 'e' + 't' + 'r' + 'o') {
  ch = gr.retro;
  cre = chalk.hex("#7d02bf");
} else if (logout === 't' + 'e' + 'e' + 'n') {
  ch = gr.teen;
  cre = chalk.hex("#fa7f7f");
} else if (logout === 's' + 'u' + 'm' + 'm' + 'e' + 'r') {
  ch = gr.summer;
  cre = chalk.hex("#f7f565");
} else if (logout === 'f' + 'l' + 'o' + 'w' + 'e' + 'r') {
  ch = gr.pastel;
  cre = chalk.hex("#6ded85");
} else if (logout === 'g' + 'h' + 'o' + 's' + 't') {
  ch = gr.mind;
  cre = chalk.hex("#95d0de");
} else if (logout === 'p'+'u'+'r'+'p'+'l'+'e') {
  ch = gr("#380478", "#5800d4", "#4687f0");
  cre = chalk.hex('#7a039e');
  } else if (logout === 'r'+'a'+'i'+'n'+'b'+'o'+'w') {
  ch = gr.rainbow
  cre = chalk.hex('#0cb3eb');
  } else if (logout === 'o'+'r'+'a'+'n'+'g'+'e') {
  ch = gr("#ff8c08", "#ffad08", "#f5bb47");
  cre = chalk.hex('#ff8400');
  } else {
  ch = gr("#243aff", "#4687f0", "#5800d4");
  cre = chalk.blueBright;

  setTimeout(() => {
    console.log(`The ${chalk.bgYellow.bold(`${config.DESIGN.Theme}`)} theme you provided does not exist!`)
}, 1000);
};

  setTimeout(() => {
    const title = _.DESIGN.Title || '';
    const asciiTitle = generateAsciiArt(title);
    console.log(
      ch.multiline('\n' + asciiTitle),
      '\n',
      ch(' ❱ ') + 'C'+'r'+'e'+'d'+'i'+'t'+'s'+' '+'t'+'o',
      cre('A'+'i'+'n'+'z'+' '+'D'+'e'+'v'+'e'+'l'+'o'+'p'+'e'+'r'),
      '\n',
      ch(' ❱ ') + `A`+`d`+`m`+`i`+`n`+`: ${cre(`${cb}`)}\n`
    );
  }, 1000);
}

module.exports = logs;