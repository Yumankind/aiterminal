#!/usr/bin/env node
import inquirer from "inquirer";
import open from "open";
//import homedir
//import os, { type } from "os";
import os, { type } from "os";
import fs from "fs";
import ora from "ora";
//import axios, { all } from "axios";
import axios from "axios";
import path from "path";
//import archiver from "archiver";
import chalk from "chalk";
//import { fileURLToPath } from "url";
//import { readFile } from "node:fs/promises";
//import { Cipher } from "crypto";
import crypto from "crypto";
//import ChildCommand from "./cmd.js";

//AI dependencies ====
import OpenAI from "openai";
import { cwd } from "node:process";
//load env variables using import
import puppeteer from "puppeteer";
//import Replicate from "replicate";

import { exec, spawn } from "child_process";
import stream from "stream";
class ChildCommand {
  constructor(
    id,
    command,
    outputCallback,
    exitCallback,
    workingDirectory = null,
    isMainCommand = false,
    debug = false
  ) {
    if (debug)
      console.log("ChildCommand constructor: ", id, command, workingDirectory);
    this.id = id;
    this.command = command;
    this.debug = debug;
    this.isMainCommand = isMainCommand;
    //max time 10 minutes
    this.child = spawn(command, {
      shell: true,
      detached: true,
      cwd: workingDirectory,
      timeout: 600000,
    });
    this.output = "";
    this.exitCallback = exitCallback;
    this.outputError = "";
    this.timeout = null;
    this.outputCallback = outputCallback;

    /*if(this.child.stdin) {
        console.log("child.stdin exists");
        this.inputStream = new stream.Readable();
        //we inject the stdinStream to the child process to avoid blocking the process
        this.inputStream.pipe(this.child.stdin);
    }*/

    this.child.stdout.on("data", (data) => {
      this.processOutut("normal", data);
    });
    this.child.stderr.on("data", (data) => {
      if (this.debug) console.error(`[${id} - ${command}] stderr: ${data}`);
      //only append data if its different from the last line
      this.processOutut("error", data);
    });
    this.child.on("error", (error) => {
      if (this.debug) console.error(`[${id} - ${command}] error: ${error}`);
      this.processOutut("error", error);
    });
    this.child.on("close", (code) => {
      if (this.debug)
        console.log(
          `[${id} - ${command}] child process exited with code ${code}`
        );
      if (this.exitCallback)
        this.exitCallback(code, this.output, this.outputError);
    });
    this.child.on("exit", (code) => {
      if (this.debug)
        console.log(
          `[${id} - ${command}] child process exited with code ${code}`
        );
      if (this.exitCallback)
        this.exitCallback(id, code, this.output, this.outputError);
    });
  }

  processOutut(type = "normal", data) {
    if (this.timeout) {
      clearTimeout(this.timeout);
    }
    if (type === "error") {
      //save data by appeding only if needed
      if (!this.outputError.endsWith(data + "\n")) {
        this.outputError += data + "\n";
      }
    } else {
      //save data by appeding only if needed
      if (!this.output.endsWith(data + "\n")) {
        this.output += data + "\n";
      }
    }
    if (!this.isMainCommand) {
      this.timeout = setTimeout(() => {
        if (this.debug)
          console.log("Timeout inside child command", this.id, this.command);
        //this.outputCallback(id, this.output, this.outputError);
        //this.output = "";
        //this.outputError = "";
        //Kill after 30 seconds of inactivity
        this.kill();
        if (this.exitCallback)
          this.exitCallback(null, this.output, this.outputError);
      }, 30000);
    } else {
      if (this.outputCallback) {
        setTimeout(() => {
          this.outputCallback(this.id, this.output, this.outputError);
          this.output = "";
          this.outputError = "";
        }, 15000);
      }
    }
  }

  setCallbacks(outputCallback, exitCallback) {
    this.outputCallback = outputCallback;
    this.exitCallback = exitCallback;
  }

  getOutput() {
    return this.output;
  }

  getOutputError() {
    return this.outputError;
  }

  input(data) {
    console.log("injecting data: ", data);
    if (!this.child.stdin) {
      console.error("child.stdin does not exist");
      return;
    }
    if (this.inputStream) {
      this.inputStream.push(data);
      this.inputStream.push(null);
      return;
    }
    this.inputStream = new stream.Readable();
    this.inputStream.push(data); // Add data to the internal queue for users of the stream to consume
    this.inputStream.push(null); // Signals the end of the stream (EOF)
    this.inputStream.pipe(this.child.stdin);
  }

  kill() {
    return this.child.kill();
  }
  //static method to generate a unique id
  static generateId() {
    return Math.random().toString(36).substring(7);
  }
}

//End AI dependencies ====

const PROMPT_TOKEN_PRICE_MILLION = 10;
const COMPLETION_TOKEN_PRICE_MILLION = 30;
const currentVersion = "0.0.1";
const supportEmail = "human@yumankind.com";
const localUrl = "http://localhost:8787";
const cipherKey =
  "2919c92ae2162429400b7acfe4d8d0f18b6f8ac385e6a6b7a3f2cdc08d2e9535:43c28737c9f80866d9bb769ff7a66d30"; //"]qK)n)G>^E>'[GPGJWw<Az$.A;@k+~";
const base64PublicKey =
  "eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjFBNFA1Q3d0MDd2ZFMxeU8zbEI4SHlPdE1KcXV6SmhPM1A5T2pWeFI5TFR2RlhZak52VG10RGNoaXI1anBENFQiLCJ5IjoiYmRvSDZKWTVTV2xzMi14SGtCclNGRDdURmJucDhTU1RxRDBtcmkxWlF6dW5lVk9CNDlyTUZDQ2pzamYtajNRciIsImNydiI6IlAtMzg0In0=";
const frontendUrl = "https://dotdev.run";
const apiUrl = process.argv.includes("--dev")
  ? "https://dotdev.powerhouse.workers.dev"
  : process.argv.includes("--local")
  ? localUrl
  : "https://api.dotdev.run";
const debug = process.argv.includes("--debug");
if (debug) {
  console.log("Debug mode enabled.");
  console.log("Using API: " + apiUrl);
}
//get system information
const systemInfo = os.platform() + " " + os.type() + " " + os.release();

const homedir = os.homedir();
const tmpdir = os.tmpdir();
const spinner = ora();
const ignore = [
  "node_modules",
  ".git",
  ".DS_Store",
  "package-lock.json",
  ".gitignore",
  "__pycache__",
  "build",
  "dist",
  ".pytest_cache",
  ".vscode",
  ".next",
  "venv",
  ".dotdev",
  ".idea",
  ".dart_tool",
  ".symlinks",
];

let prompt = null;
let token = null;
let plan = null;
let openai = null;
let openAiClient = null;
let user = null;
let deviceId = null;
let license = null;
let price = null;
//full scope
let packageName = null;
let packageVersion = null;
let discountCode = null;

//new package information
let currency = null;
let oneTimePrice = null;
let subscriptionPrice = null;
let lifetimePrice = null;
let discountForNewCustomers = null;
let discountForNewCustomersDuration = null;
let publicECKey = null;

async function generateECKey() {
  let key = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-384",
    },
    true,
    ["sign", "verify"]
  );
  //export public key
  let publicKey = await crypto.subtle.exportKey("jwk", key.publicKey);
  //convert to base64
  publicECKey = publicKey;
  publicKey = Buffer.from(JSON.stringify(publicKey)).toString("base64");
  console.log("Public key: ", publicKey);
  //export private key
  let privateKey = await crypto.subtle.exportKey("jwk", key.privateKey);
  privateKey = Buffer.from(JSON.stringify(privateKey)).toString("base64");
  console.log("Private key: ", privateKey);
  return key.publicKey;
}

async function importECKeyBase64(keyData, isPublic) {
  keyData = JSON.parse(Buffer.from(keyData, "base64").toString());
  let key = await crypto.subtle.importKey(
    "jwk",
    keyData,
    {
      name: "ECDSA",
      namedCurve: "P-384",
    },
    true,
    isPublic ? ["verify"] : ["sign"]
  );
  return key;
}

async function changePlan(account = false) {
  await needsToken();
  //create payment session
  let url = apiUrl + "/buy-plan";
  let data = {
    email: user.email,
    plan: "unlimited",
    referalCode: discountCode,
    currency: currency || "eur",
  };

  if (debug) {
    console.log("sending data", data);
  }

  try {
    //loading
    spinner.start();
    spinner.text = "Creating payment session...";
    let response = await axios.post(url, data);
    console.log(response);
    if (response.status === 200) {
      spinner.succeed();
      if (response.data.message) {
        console.log(response.data.message);
      }
      console.log("Click to pay: " + response.data.url);
      open(response.data.url);
      process.exit(0);
    } else {
      spinner.fail();
      console.log(chalk.red(e.response.data.message));
    }
  } catch (e) {
    spinner.fail();
    console.log(chalk.red(e.response.data.message));
  }
}

async function needsToken() {
  if (token === null) {
    if (debug) console.log("token is null. Force login");
    //login
    let result = await login();
    if (!result) {
      process.exit(0);
    }
  }
}

function gatherUserInformation() {
  return new Promise(async (resolve, reject) => {
    if (deviceId === null) {
      deviceId = Math.random().toString(36).substring(2, 15);
    }
    let u = {};
    while (!u.email) {
      let answers = await inquirer.prompt([
        {
          type: "input",
          name: "email",
          message:
            "What is your e-mail? (your purchases will be associated to this e-mail)",
        },
      ]);
      let confirmation = await inquirer.prompt([
        {
          type: "confirm",
          name: "confirmation",
          message: "Is your e-mail correct? " + answers.email,
        },
      ]);
      if (confirmation.confirmation) {
        //save user
        u.email = answers.email;
        u.deviceId = deviceId;
        fs.writeFileSync(homedir + "/.dotdev", JSON.stringify(u));
      }
    }
    resolve(u);
  });
}

async function downloadProgress(progress) {
  spinner.start();
  let blocks = (progress * 20) / 100;
  let text = "[";
  for (let i = 0; i < blocks; i++) {
    text += "▉";
  }
  for (let i = 0; i < 20 - blocks; i++) {
    text += " ";
  }
  text += "]";
  spinner.text = text;
}

function readFiles(dir, processFile) {
  try {
    let fileNames = fs.readdirSync(dir);
    fileNames.forEach((fileName) => {
      if (ignore.includes(fileName)) {
        return;
      }
      const name = path.parse(fileName).name;
      // get current file extension
      const ext = path.parse(fileName).ext;
      // get current file path
      const filepath = path.resolve(dir, fileName);
      let stat = fs.statSync(filepath);
      // check if the current path is a file or a folder
      const isFile = stat.isFile();
      // exclude folders
      if (isFile) {
        // callback, do something with the file
        processFile(filepath, name, ext, stat);
      } else {
        readFiles(filepath, processFile);
      }
    });
  } catch (e) {
    console.err(e);
  }
}

//MAIN ACTIONS

async function login() {
  if (user === null) {
    user = await gatherUserInformation();
  }
  spinner.start();
  spinner.text = "Logging in...";
  let url = apiUrl + "/login";
  try {
    let response = await axios.post(url, {
      email: user.email,
      deviceId: deviceId,
      homedir: homedir,
    });
    spinner.stop();
    //save loginId and ask for loginCode sent by e-mail
    const loginId = response.data.id;
    //say to check the SPAM folder
    console.log(response.data.message);
    console.log(
      chalk.dim("Check your inbox or SPAM folder for the login code.")
    );
    let answers = await inquirer.prompt([
      {
        type: "input",
        name: "loginCode",
        message: "Insert your login code here:",
      },
    ]);
    //verify login code
    let loginCode = answers.loginCode;
    //remove other characters than numbers
    loginCode = loginCode.replace(/\D/g, "");
    if (debug) console.log("clean loginCode", loginCode);
    try {
      let response = await axios.post(apiUrl + "/verify-login-code", {
        email: user.email,
        code: loginCode,
        loginId: loginId,
      });
      spinner.succeed("Logged in!");
      token = response.data.token;
      plan = response.data.plan;
      license = response.data.license;
      //save token
      fs.writeFileSync(
        tmpdir + "/.dotdev-session",
        JSON.stringify({
          token: token,
          plan: plan,
          license: license,
        })
      );
      spinner.stop();
      return true;
      //process.exit(0);
    } catch (e) {
      if (debug) console.error(e);
      spinner.fail(e.response.data.message);
      spinner.stop();
      console.log(
        chalk.dim(
          "If you are having difficulties, please contact " +
            supportEmail +
            " with the error message."
        )
      );
      return false;
    }
  } catch (e) {
    if (debug) console.error(e);
    spinner.fail(e.response.data.message);
    spinner.stop();
    console.log(
      chalk.dim(
        "If you are having difficulties, please contact " +
          supportEmail +
          " with the error message."
      )
    );
    return false;
  }
}

async function checkOpenAiKey() {
  let keyparts = cipherKey.split(":");
  let key = Buffer.from(keyparts[0], "hex");
  let iv = Buffer.from(keyparts[1], "hex");
  if (fs.existsSync(homedir + "/.openai")) {
    let encrypted = fs.readFileSync(homedir + "/.openai").toString();
    let encryptedBuffer = Buffer.from(encrypted, "hex");
    //let decipher = crypto.createDecipher("aes-256-cbc", cipherKey);
    //initial vector for the OCB mode should be 12 octets; 96 bits
    //do not use createDecipher
    let decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedBuffer);
    //let decrypted = decipher.update(encrypted, "hex", "utf8");
    //decrypted += decipher.final("utf8");
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    openai = decrypted.toString();
  }
  if (openai === null) {
    let answers = await inquirer.prompt([
      {
        type: "input",
        name: "openai",
        message: "Insert your OpenAI key here:",
        validate: function (value) {
          if (value.length > 0) {
            return true;
          } else {
            return "Please insert your OpenAI key. Go to https://platform.openai.com/account/api-keys to get a key.";
          }
        },
      },
    ]);
    openai = answers.openai;
    if (debug) console.log("openai", openai);
    //test key
    try {
      openAiClient = new OpenAI({
        apiKey: openai,
      });
    } catch (e) {
      openai = null;
    }
    if (openai && openai.length > 0) {
      //encrypt and save
      //let cipher = crypto.createCipher("aes-256-cbc", cipherKey);
      let cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

      let encrypted = cipher.update(openai);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      fs.writeFileSync(homedir + "/.openai", encrypted.toString("hex"));
    } else {
      console.log(
        "A valid OpenAI key is required to use this service. Go to https://platform.openai.com/account/api-keys to get your key."
      );
      process.exit(0);
    }
  }
}

async function verifyLicense() {
  if (debug) console.log("License:", license);
  if (license) {
    spinner.start();
    //verify license
    spinner.text = "Verifying license...";
    if (publicECKey === null) {
      //publicECKey = await generateECKey();
      publicECKey = await importECKeyBase64(base64PublicKey, true);
    }

    //verify license signature (licenca = email + homedir)
    const valueCheck = Buffer.from(user.email + ":" + homedir);
    if (debug) console.log("license", license);
    //license base64
    let licenseBuffer = Buffer.from(license, "base64");
    const result = await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-384" },
      },
      publicECKey,
      licenseBuffer,
      valueCheck
    );
    if (result) {
      spinner.succeed("License verified!");
      return true;
    } else {
      spinner.fail("Invalid license!");
      return false;
    }
  } else {
    //spinner.fail("License not found.");
    return false;
  }
}

function dotDevExplanation() {
  console.log("Welcome to " + chalk.bold("[⏺︎_] DotDev!"));
  console.log("");
  console.log(
    "DotDev allows you to create and edit software using natural language."
  );
  console.log(chalk.bold("It reduces the time to create software by 98% and increase your productivity by 60x."));
  console.log(
    chalk.dim.italic(
      "1h of work done in 1 minute. 1 day of work done in 10 minutes. 1 week of work done in 1h20m."
    )
  );
  console.log("");
  console.log("FEATURES");
  console.log(
    "- From task to specification, to code in seconds: quick prototyping, iteration and testing"
  );
  console.log("- Quickly create custom boilerplate code for your tech stack");
  console.log(
    "- Generate or edit code for any language, framework or platform"
  );
  console.log("- Add new features to your software in an instant");
  console.log(
    "- Integrate Dockerfiles, Terraform and Kubernetes yaml, database schemas and more to your project"
  );
  console.log("- Create documentation, tests and reports automatically");
  console.log(chalk.dim("Powered by OpenAI GPT-4o"));
  console.log("");
  console.log("Before continuing, we need to set up a few things.");
}

async function checkLicense() {
  //get latest plan of the user and its licence
  await getUserPlan();
  let licenseValid = await verifyLicense();
  //get last data of the user

  //verify if the user has a plan
  if (!licenseValid && plan !== "unlimited") {
    //getting price
    spinner.start();
    spinner.text = "Checking plan...";
    try {
      let response = await axios.get(apiUrl + "/price");
      spinner.succeed("Plan checked!");
      price = response.data;
      if (debug) console.log("price", price);
    } catch (e) {
      spinner.fail(e.response.data.message);
      if (e.response.data.actions && e.response.data.actions.length > 0) {
        await processReply(e.response.data.actions);
        await checkLicense();
      } else {
        process.exit(0);
      }
    }
    let currentPrice = (price.normal - price.amount_off) / 100;
    let discount = Math.ceil((price.amount_off / price.normal) * 100);
    let priceSymbol = price["currency"] == "eur" ? "€" : "$";
    console.log(
      "To use this service in your own terminal you need to have the " +
        proBanner() +
        " plan."
    );
    console.log("");

    console.log(
      "The " +
        proBanner() +
        " plan of DotDev allows you to manipulate software on your own computer using the AI terminal without any limits*."
    );
    console.log("It includes:");
    console.log(
      "- Unlimited software editing and generation using natural language"
    );
    console.log("- Automatic documentation and inline comments");
    console.log("- Automatic testing and reports");
    console.log("- Best practices and code formatting");
    console.log("- Automatic code review, suggestions and improvements");
    console.log("- Instant commit message generation");
    console.log("- No monthly or usage fees*");
    console.log("- Future updates to [⏺︎_] DotDev");
    console.log("- Support by e-mail " + chalk.dim("- " + supportEmail));
    console.log("");
    console.log(
      chalk.dim(
        "Prices in EUR. VAT not included. Prices may change without notice."
      )
    );
    console.log(
      chalk.dim(
        "*This plan needs a valid OpenAI key to work. You can get one at https://platform.openai.com/account/api-keys"
      )
    );
    console.log("");
    console.log(
      chalk.bold(
        "Price: " +
          chalk.strikethrough.dim(price["normal"] / 100 + priceSymbol) +
          " " +
          currentPrice +
          priceSymbol
      )
    );
    console.log(
      chalk.bgRedBright(
        " -" + discount + "% " + " " + price["discount_name"] + " "
      ) + chalk.redBright(" - only " + price.discounts_left + " left")
    );

    let answers = await inquirer.prompt([
      {
        type: "confirm",
        name: "upgrade",
        message:
          "Do you want to upgrade now and get the limited time discount?",
      },
    ]);
    if (answers.upgrade) {
      await changePlan();
    } else {
      //exit
      console.log("We hope to see you soon! Happy coding!");
      console.log(
        chalk.dim(
          "Pst... check our website. We usually run promotions for the unlimited plan: https://dotdev.run"
        )
      );
      process.exit(0);
    }
    //register device
    await registerLicense();
  } else if (!licenseValid && plan === "unlimited") {
    console.log("Only one device is allowed to be registered at a time.");
    //ask user to register device
    let answers = await inquirer.prompt([
      {
        type: "confirm",
        name: "response",
        message:
          "Do you want to replace all other devices for the current one? " +
          chalk.redBright(
            "The other devices will stop working and require to be registered again."
          ),
      },
    ]);
    if (answers.response) {
      await registerLicense();
    } else {
      exit();
    }
  }
}

async function checkVersion() {
  try {
    //check if this app is up to date
    let response = await axios.get(apiUrl + "/version");
    let lastVersion = response.data.version;
    if (debug) console.log("Current version: " + currentVersion);
    if (debug) console.log("Latest version: " + lastVersion);
    if (lastVersion !== currentVersion) {
      console.log(
        "There is a new version available (" +
          lastVersion +
          "). Please update go to " +
          frontendUrl +
          " to the latest version."
      );
      open(frontendUrl);
      process.exit(0);
    }
  } catch (e) {
    //silence error
    if (debug) console.error(e);
  }
}

async function registerLicense() {
  //register device
  spinner.start();
  spinner.text = "Registering device...";
  try {
    let response = await axios.post(apiUrl + "/register-device", {
      token: token,
      email: user.email,
      hd: homedir,
    });
    if (debug) console.log(response.data);
    license = response.data.license;
    //update session
    fs.writeFileSync(
      tmpdir + "/.dotdev-session",
      JSON.stringify({
        token: token,
        plan: plan,
        license: license,
        price: null,
      })
    );
    spinner.succeed("Device registered!");
  } catch (e) {
    spinner.fail(e.response.data.message);
    if (e.response.data.actions && e.response.data.actions.length > 0) {
      await processReply(e.response.data.actions);
      await registerLicense();
    } else {
      process.exit(0);
    }
  }
}

async function processReply(actions) {
  if (debug) console.log("processReply", actions);
  let action = null;
  if (actions.length === 1) {
    action = actions[0];
  } else if (actions.length > 1) {
    //show options
    let answers = await inquirer.prompt([
      {
        type: "list",
        name: "action",
        message: "What do you want to do?",
        choices: actions,
        loop: false,
      },
    ]);
    action = answers.action;
  } else {
    //there is no options. Exit
    process.exit(0);
  }
  if (action === "login") {
    await login();
  } else if (action === "run") {
    await run();
  } else if (action === "download") {
    await download();
  } else if (action === "buy") {
    await buy();
  }
}

async function download() {
  await needsToken();
  //TODO
  await new Promise((resolve) => setTimeout(resolve, 1000));
  spinner.info("Downloading package...");
  await new Promise((resolve) => setTimeout(resolve, 1000));
  await downloadProgress();
  spinner.succeed("Package installed!");
}

async function buy(packageId, plan, referalCode) {
  await needsToken();
  spinner.text = "Creating checkout session...";
  spinner.start();
  try {
    let response = await axios.post(apiUrl + "/buy", {
      email: user.email,
      token: token,
      packageId: packageId,
      plan: plan,
      referalCode: referalCode,
    });
    spinner.succeed();
    console.log(response.data.message);
    console.log("Click to pay: " + response.data.url);
    open(response.data.url);
    process.exit(0);
  } catch (e) {
    spinner.fail();
    if (
      e.response &&
      e.response.data &&
      e.response.data.actions &&
      e.response.data.actions.length > 0
    ) {
      spinner.info(e.response.data.message);
      await processReply(e.response.data.actions);
      await buy(packageId, plan, referalCode);
    } else {
      spinner.text = e.response.data.message;
      spinner.fail();
      process.exit(0);
    }
  }
}

function printProfile(profile) {
  console.log("👤 " + chalk.bold(user.email));
  console.log("📦 Plan: " + chalk.bold(profile.plan ? profile.plan : "Free"));
  /*if (profile.plan && profile.plan !== "free") {
    //expiration date
    console.log("📅 Plan expiration: " + chalk.bold(profile.expiration));
  }*/
  console.log(
    "🔗 Referral code: " +
    (profile.referal && profile.referal != null ? chalk.bold(profile.referal) : '---')
  );
  //show how much you earned
  //referal earnings
  console.log(
    "📈 Referral earnings: " +
      chalk.bold(
        (profile.referralEarnings ? profile.referralEarnings : "0") +
          (profile.currency || "EUR")
      ) +
      chalk.dim(" - you earned this amount by referring new users")
  );
  console.log("");
  /*console.log("📦 Packages:");
  //ORDER OWN PACKAGES FIRST and then the others? or split?
  if (profile.packages && profile.packages.length > 0) {
    profile.packages.forEach((p) => {
      console.log(
        "  - " +
          chalk.bold(p.name) +
          "@" +
          chalk.dim(p.version) +
          " - " +
          chalk.dim(p.expiration)
      );
    });
  } else {
    console.log(chalk.dim("   You don't have any packages yet."));
  }*/
  //console.log("");
}

function printStripeSubscriptions(subscriptions, askToCancel = false) {
  console.log("💸 Active subscriptions:");
  if (subscriptions && subscriptions.length > 0) {
    let options = subscriptions
      .filter((el) => el.status == "active" && el.cancel_at_period_end == false)
      .map((s) => {
        //console.log(s.metadata.packageId);
        return {
          name:
            (askToCancel ? "" : "   ") +
            (s.metadata.packageId ? s.metadata.packageId + " package - " : "") +
            (s.metadata.pricePlan
              ? s.metadata.pricePlan.toUpperCase()
              : "No name") +
            chalk.dim(
              " " +
                s.plan.amount / 100 +
                " " +
                s.plan.currency.toUpperCase() +
                "/" +
                s.plan.interval
            ) +
            ": " +
            chalk.dim(
              new Date(s.current_period_start * 1000).toLocaleDateString()
            ) +
            " - " +
            chalk.dim(
              new Date(s.current_period_end * 1000).toLocaleDateString()
            ),
          value: s.id,
        };
      });
    //console.log(options);
    if (askToCancel) {
      options.push({
        name: "Exit",
        value: "exit",
      });
      return inquirer.prompt([
        {
          type: "list",
          name: "subscriptionId",
          message: "Choose the subscription to cancel:",
          choices: options,
        },
      ]);
    } else {
      options.forEach((o) => {
        console.log(o.name);
      });
    }
  } else {
    console.log(
      chalk.dim(
        (askToCancel ? "" : "    ") + "You don't have any subscriptions yet."
      )
    );
    return null;
  }
  console.log("");
}

async function profile() {
  await needsToken();
  //TODO: show user profile
  //activate spinner
  spinner.start();
  spinner.text = "Loading profile...";
  try {
    let response = await axios.post(apiUrl + "/profile", {
      email: user.email,
      token: token,
    });
    spinner.text = "Profile loaded!";
    spinner.succeed();
    console.log("");
    printProfile(response.data.user);
    //rintStripeSubscriptions(response.data.subscriptions);
  } catch (e) {
    if (
      e.response &&
      e.response.data &&
      e.response.data.actions &&
      e.response.data.actions.length > 0
    ) {
      spinner.info(e.response.data.message);
      await processReply(e.response.data.actions);
      await profile();
    } else {
      spinner.text = e.response.data.message;
      spinner.fail();
      process.exit(0);
    }
  }
  //show personal discount code + referral code
  //show packages + expiration date for each
  //show plan and number of packages available (if pro)
  //show options - sellet stats, referal stats, change plan
}

async function getUserPlan() {
  try {
    let response = await axios.post(apiUrl + "/profile", {
      email: user.email,
      token: token,
    });
    plan = response.data.plan;
    license = response.data.license;
    //save token
    fs.writeFileSync(
      tmpdir + "/.dotdev-session",
      JSON.stringify({
        token: token,
        plan: plan,
        license: license,
      })
    );
  } catch (e) {
    if (
      e.response &&
      e.response.data &&
      e.response.data.actions &&
      e.response.data.actions.length > 0
    ) {
      spinner.info(e.response.data.message);
      await processReply(e.response.data.actions);
      await getUserPlan();
    } else {
      spinner.fail(e.response.data.message);
      process.exit(0);
    }
  }
}

function proBanner() {
  return chalk.bgWhite(chalk.bgBlueBright(chalk.italic(" UNLIMITED ")));
}

async function logout() {
  let user = null;
  if (fs.existsSync(homedir + "/.dotdev")) {
    let result = fs.unlinkSync(homedir + "/.dotdev");
  }
  if (fs.existsSync(tmpdir + "/.dotdev-session")) {
    let result2 = fs.unlinkSync(tmpdir + "/.dotdev-session");
  }
  //remove openai key
  if (fs.existsSync(homedir + "/.openai")) {
    let result3 = fs.unlinkSync(homedir + "/.openai");
  }
  console.log("Logged out!");
}

function humanReadableEllapsedTime(diff) {
  let ellapsedTime = diff / 1000;
  let savedTime = ellapsedTime * 15;
  let savedTimeHours = Math.floor(savedTime / 3600);
  let savedTimeMinutes = Math.floor((savedTime % 3600) / 60);
  let savedTimeSeconds = Math.floor(savedTime % 60);
  return (
    "You have saved " +
    savedTimeHours > 0 ? savedTimeHours + " hours, " : "" +
    savedTimeMinutes +
    " minutes and " +
    savedTimeSeconds +
    " seconds"
  );
}


function exit() {
  if(runningCommands.length > 0) {
    //kill all commands
    runningCommands.forEach((cmd) => {
      cmd.command.kill();
    });
  }

  if (outputTokens > 0) {
    console.log("=== STATS ===");
    let ellapsedTime = (new Date().getTime() - time.start) / 1000;
    console.log(chalk.bold("Saved time: " + humanReadableEllapsedTime(ellapsedTime * 1000)));
    console.log("Ellapsed time: " + ellapsedTime + " seconds");
    console.log("Input tokens: " + inputTokens);
    console.log("Output tokens: " + outputTokens);
    console.log(
      "Cost: " +
        (inputTokens * (PROMPT_TOKEN_PRICE_MILLION / 1000000) +
          outputTokens * (COMPLETION_TOKEN_PRICE_MILLION / 1000000)) +
        " USD"
    );
  }
  console.log("Goodbye! Happy coding!");
  process.exit(0);
}

async function run() {
  await needsToken();
  await checkLicense();
  await checkOpenAiKey();
  //send to API
  await runMainAgent(prompt);
}

async function test() {
  await needsToken();
  await checkLicense();
  await checkOpenAiKey();
  spinner.info("Testing code...");
  await tester();
  spinner.succeed("Code tested and report generated!");
}

async function commit() {
  await needsToken();
  await checkLicense();
  await checkOpenAiKey();
  //create commit message based on the changes
  await commitAgent();
}

async function main() {
  console.log("[⏺︎_] DOTDEV ::: AI terminal for developers :::");
  let noflags = process.argv.filter((arg) => !arg.startsWith("-"));
  let action = noflags[2] ? noflags[2] : "none";

  if (fs.existsSync(homedir + "/.dotdev")) {
    if (debug) console.log("User data found!");
    let userRaw = fs.readFileSync(homedir + "/.dotdev").toString();
    user = JSON.parse(userRaw);
    if (user.deviceId) {
      deviceId = user.deviceId;
    }
  } else {
    dotDevExplanation();
  }
  //read session token
  if (fs.existsSync(tmpdir + "/.dotdev-session")) {
    if (debug) console.log("Session token found!");
    let sessionRaw = fs.readFileSync(tmpdir + "/.dotdev-session").toString();
    let session = JSON.parse(sessionRaw);
    token = session.token;
    if (session.plan) {
      plan = session.plan;
    }
    if (session.license) {
      license = session.license;
    }
    if (session.price) {
      price = session.price;
    }
  }

  if (debug) console.log("Action:", action);

  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log("Usage: dotdev [action]");
    console.log("Actions:");
    console.log("  run\t\tCreate or edit software by request");
    console.log("  test\t\tTest the software in the current folder");
    //console.log("  commit\tCreate a commit message based on the changes");
    console.log("  login\t\tLogin to your account");
    console.log("  logout\tLogout from your account");
    if (debug) console.log("  keys\t\tGenerate EC keys for signing");
    console.log("  help\t\tShow this help message");
    console.log("  exit\t\tExit the program");
    process.exit(0);
  }

  if (action == "logout") {
    await logout();
    process.exit(0);
  } else if (action == "keys" && debug) {
    const key = crypto.randomBytes(32);
    console.log("encryption key:", key.toString("hex"));
    // Defining iv
    const iv = crypto.randomBytes(16);
    console.log("iv:", iv.toString("hex"));
    await generateECKey();
    process.exit(0);
  }
  await checkVersion();

  while (true) {
    if (action === "none") {
      if (user === null || deviceId === null) {
        user = await gatherUserInformation();
      } else {
        console.log(chalk.dim("Logged in as " + user.email));
        console.log("");
      }
      let choices = [
        {
          name: "create or edit software",
          value: "run",
          short: "Create or edit software by request",
        },
        /*{
          name: "test the software in the current folder",
          value: "test",
          short: "Test the software",
        },
        {
          name: "create a commit message based on the changes",
          value: "commit",
          short: "Automatically generate a commit message",
        },*/
        new inquirer.Separator(),
        /*{
          name: chalk.bold("Upgrade to " + proBanner()),
          value: "upgrade",
          short: "Upgrade to the unlimited plan",
        },*/
      ];
      if (user === null) {
        choices.push("login");
      } else {
        choices.push({
          name: "profile",
          value: "profile",
          short: "Profile",
        });
        choices.push("logout");
      }
      choices.push("help");
      choices.push("exit");
      let answers = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What do you want to do?",
          choices: choices,
          loop: false,
        },
      ]);
      action = answers.action;
    } else if (action === "exit") {
      exit();
    } else if (action === "run") {
      //get user prompt
      prompt = "";
      //after action
      let ignoreArgs = true;
      noflags.forEach((arg, index) => {
        if (!ignoreArgs) {
          if (prompt.length > 0) {
            prompt += " ";
          }
          prompt += arg;
        }
        if (arg === "run") {
          ignoreArgs = false;
        }
      });

      if (debug) console.log("Prompt:", prompt);

      if (user === null || deviceId === null) {
        user = await gatherUserInformation();
      } else {
        console.log(chalk.dim("Logged in as " + user.email));
        console.log("");
      }
      await run();
      process.exit(0);
    } else if (action === "test") {
      if (user === null || deviceId === null) {
        user = await gatherUserInformation();
      } else {
        console.log(chalk.dim("Logged in as " + user.email));
        console.log("");
      }
      await test();
      process.exit(0);
    } else if (action === "commit") {
      if (user === null || deviceId === null) {
        user = await gatherUserInformation();
      } else {
        console.log(chalk.dim("Logged in as " + user.email));
        console.log("");
      }
      await commit();
      process.exit(0);
    } else if (action === "logout") {
      await logout();
      process.exit(0);
    } else if (action === "login") {
      await login();
      process.exit(0);
    } else if (action === "buy") {
      if (user === null || deviceId === null) {
        user = await gatherUserInformation();
      } else {
        console.log(chalk.dim("Logged in as " + user.email));
        console.log("");
      }
      await buyUnlimited();
      process.exit(0);
    } else if (action == "profile") {
      await profile();
      process.exit(0);
    } else if (action == "help") {
      console.log(
        "If you need help or have a new feature request, please send a message to human@yumankind.com"
      );
      console.log("Happy coding!");
      process.exit(0);
    } else {
      console.log("Invalid action");
      process.exit(1);
    }
  }
}

//AI SYSTEM
let conversationMemory = [];
let agentMessages = [];
let folderFiles = [];
let numAttempts = 0;
let maxAttempts = 3;
let time = {};
let workingDirectory = cwd();
const originalWorkingDirectory = cwd();
let hasSoftwareSpecifications = false;
let hasSoftwarePlan = false;
let inputTokens = 0;
let outputTokens = 0;
let softwareData = {};
let currentStep = 1;
let runner = null;
let isGit = false;
let unsplashAccessKey = null;

//get list of files in the current directory
function readFolderFiles() {
  //always reset stucture
  folderFiles = [];
  spinner.info("Reading files from current folder");
  let files = fs.readdirSync(originalWorkingDirectory, { recursive: true });
  files.forEach((file) => {
    //verify if the file is in the ignore list (any part of the path is in the ignore list)
    if (ignore.some((i) => file.includes(i))) {
      return;
    }
    let name = file;

    //verify if the file exists
    if (!fs.existsSync(file)) {
      if (debug) console.log("File not found", file);
      return;
    }

    if (fs.lstatSync(file).isDirectory()) {
      name = file + "/";
    }
    if (!folderFiles.includes(name)) {
      if (debug) console.log("found new file", file);
      //verify if the file is a folder
      folderFiles.push(name);
    }
  });
  //order files
  folderFiles.sort();
  if (debug) console.log("Files in folder: ", folderFiles);
}

//possible commands:
//open a file
async function openFile({ file }) {
  //verify if file starts with /
  /*f (file.startsWith("/")) {
    file = file.slice(1);
  }*/
  let absolutePath = path.join(originalWorkingDirectory, file);
  if (debug) console.log("Absolute path", absolutePath);

  if (fs.existsSync(absolutePath)) {
    //open file
    let data = fs.readFileSync(absolutePath, "utf8");
    if (debug) console.log("Got file data with a leght " + data.length);
    return "File content:\n" + data;
  } else {
    return "File not found at " + file;
  }
}

//create a file
async function createFileInCurrentDirectory({ fileName, content }) {
  if (content) {
    //create file
    if (debug) console.log("Creating file", fileName, "with content", content);
    //verify if the folder exist
    let absolutePath = path.join(originalWorkingDirectory, fileName);
    let subfolders = fileName.split("/");
    if (subfolders.length > 1) {
      let folder = subfolders.slice(0, subfolders.length - 1).join("/");
      if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
        if (debug) console.log("Folders created" + folder);
      }
    }

    try {
      //write file in the working directory
      fs.writeFileSync(absolutePath, content);
      //add file to folderFiles
      folderFiles.push(fileName);
      return "File created";
    } catch (err) {
      console.error(err);
      return "Error creating file";
    }
  } else {
    return "Error: The content of the file cannot be empty";
  }
}

//create folder
async function createFolder({ folderName }) {
  //create folder
  let absolutePath = path.join(originalWorkingDirectory, folderName);
  if (debug) console.log("Creating folder", absolutePath);
  //verify if the folder exist
  if (!fs.existsSync(absolutePath)) {
    fs.mkdirSync(absolutePath, { recursive: true });
    if (debug) console.log("Folder created" + absolutePath);
    return "Folder created";
  } else {
    if (debug) console.log("Folder already exists");
    return "Folder already exists";
  }
}

//delete a file
async function deleteFile({ file }) {
  let absolutePath = path.join(originalWorkingDirectory, file);
  //check if file exists
  if (fs.existsSync(absolutePath)) {
    try {
      //delete file in the working directory, sync
      fs.unlinkSync(absolutePath);
      //remove file from folderFiles
      readFolderFiles();
      return "File deleted";
    } catch (err) {
      console.error(err);
      return "Error deleting file";
    }
  } else {
    if (debug) console.log("File not found at " + file);
    return "File not found at " + file;
  }
}
//rename a file
async function renameFile({ oldFilePath, newFilePath }) {
  let absolutePath = path.join(originalWorkingDirectory, oldFilePath);
  let newAbsolutePath = path.join(originalWorkingDirectory, newFilePath);

  //check if file exists
  if (!fs.existsSync(absolutePath)) {
    if (debug) console.log("File not found at " + oldFilePath);
    return "File not found at " + oldFilePath;
  }
  //rename file in the working directory, sync
  try {
    fs.renameSync(absolutePath, newAbsolutePath);
    //update folderFiles
    readFolderFiles();
    return "File renamed";
  } catch (err) {
    console.error(err);
    return "Error renaming file";
  }
}
//ask user for any inputs for environment variables or other question you need to ask
async function askUser({ question }) {
  try {
    let response = await inquirer.prompt([
      {
        type: "input",
        name: "response",
        message: question,
      },
    ]);
    console.log("Thank you!");
    return response.response;
  } catch (err) {
    if (debug) console.error(err);
    return "Error asking user: " + err;
  }
}

//markspecifications as ready
async function specificationsReady({ softwareSpecifications }) {
  hasSoftwareSpecifications = true;
  if (debug) console.log("Software specifications ready!");
  softwareData["specifications"] = softwareSpecifications;
  if (debug) console.log("=== SPECIFICATIONS ===");
  if (debug) console.log(softwareSpecifications);
  if (debug)
    console.log("Time taken: " + (new Date() - time.specifications) + "ms");
  //write the plan to a file in the working directory .dotdev/plan.md
  //ensure folder exists
  if (!fs.existsSync(path.join(originalWorkingDirectory, ".dotdev"))) {
    fs.mkdirSync(path.join(originalWorkingDirectory, ".dotdev"));
  }
  fs.writeFileSync(
    path.join(originalWorkingDirectory, ".dotdev/specifications.md"),
    softwareSpecifications
  );
}

async function softwarePlanReady({ softwarePlan }) {
  hasSoftwarePlan = true;
  softwareData["plan"] = softwarePlan;
  if (debug) console.log("Plan ready!");
  if (debug) console.log("=== PLAN ===");
  if (debug) console.log(softwarePlan);
  if (debug) console.log("Time taken: " + (new Date() - time.plan) + "ms");
  //write the plan to a file in the working directory .dotdev/plan.md
  //ensure folder exists
  if (!fs.existsSync(path.join(originalWorkingDirectory, ".dotdev"))) {
    fs.mkdirSync(path.join(originalWorkingDirectory, ".dotdev"));
  }
  fs.writeFileSync(
    path.join(originalWorkingDirectory, ".dotdev/plan.md"),
    softwarePlan
  );
}

//replace content file
async function replaceContentFile({ file, content }) {
  if (debug)
    console.log("Replacing content of file ", file, " with new content");
  let absolutePath = path.join(originalWorkingDirectory, file);
  //check if file exists
  if (fs.existsSync(absolutePath)) {
    fs.writeFileSync(absolutePath, content);
    return "File content replaced";
  } else {
    if (debug) console.log("File not found at " + file);
    return "File not found at " + file;
  }
}

function autoFixPath(originalPath) {
  //check if the path is relative
  //take originalWorkingDirectory and add the path
  //remove originalWorkingDirectory from the path
  let newPath = originalPath.replace(originalWorkingDirectory, "");
  let newSplit = newPath.split("/");
  //if the firs 2 elements are the same, remove the first one
  if (newSplit[0] === newSplit[1]) {
    newSplit.shift();
    console.log("Fixed absolute path: " + newSplit.join("/"));
  }
  return path.join(originalWorkingDirectory, newSplit.join("/"));
}

async function appendContentToFile({ file, content }) {
  if (debug) console.log("Appending content to file ", file);
  let absolutePath = path.join(originalWorkingDirectory, file);
  if (debug) console.log("Absolute path", absolutePath);

  if (fs.existsSync(absolutePath)) {
    //append content to file in the working directory, sync
    fs.appendFileSync(absolutePath, content);
    return "File content appended";
  } else {
    if (debug)
      console.log("File not found. Current directory: " + workingDirectory);
    return "File not found. Current directory: " + workingDirectory;
  }
}

//generate and download image
/*async function generateImage({ prompt, filePath }) {
  const replicate = new Replicate({
    auth: REPLICATE_KEY,
  });
  const input = {
    prompt: prompt,
    scheduler: "K_EULER",
  };
  if (debug) console.log("Generating image...");
  const output = await replicate.run(
    "stability-ai/stable-diffusion:ac732df83cea7fff18b8472768c88ad041fa750ff7682a21affe81863cbe77e4",
    { input }
  );

  if (debug) console.log(output);
  //output is a list of urls
  //download the image
  const url = output[0];
  const response = await fetch(url);
  const buffer = await response.buffer();
  fs.writeFileSync(filePath, buffer);
  return "Image generated and saved in path: " + filePath;
}*/

//save software plan step
async function saveSoftwarePlanStep({ stepNumber, stepData }) {
  if (debug) console.log("Saving software plan step", stepNumber);
  try {
    //save each step to the folder .dotdev/
    if (!fs.existsSync(path.join(originalWorkingDirectory, ".dotdev"))) {
      fs.mkdirSync(path.join(originalWorkingDirectory, ".dotdev"));
    }
    fs.writeFileSync(
      path.join(originalWorkingDirectory, ".dotdev/step-" + stepNumber + ".md"),
      stepData
    );
    return "Step saved";
  } catch (err) {
    console.error(err);
    return "Error saving step";
  }
}

//get all the files with the step data
async function getSoftwarePlanSteps() {
  if (debug) console.log("Getting software plan steps");
  let steps = [];
  //get all files in the folder .dotdev/
  let files = fs.readdirSync(path.join(originalWorkingDirectory, ".dotdev"));
  files.forEach((file) => {
    if (file.startsWith("step-")) {
      let stepNumber = file.split("-")[1].split(".")[0];
      let data = fs.readFileSync(
        path.join(originalWorkingDirectory, ".dotdev", file),
        "utf8"
      );
      steps.push({ stepNumber: stepNumber, data: data, status: "pending" });
    }
  });
  //order steps by step number
  steps.sort((a, b) => {
    return a.stepNumber - b.stepNumber;
  });
  return steps;
}

let runningCommands = [];
//TODO: save the output of all child processes?

//run command
async function runCommand({ command, isMainCommandToRunTheSoftware }) {
  workingDirectory = originalWorkingDirectory;
  if (command.startsWith("rm ") || command.startsWith("mkdir ")) {
    return "Command not allowed. To access or manipulate files use the other functions that you have available: renameFile, deleteFile, createFolder, createFileInCurrentDirectory and openFile with the relative path from the root.";
  }

  let subcommands = command.split("&&");

  if (subcommands[0].startsWith("cd ")) {
    let newDirectory = subcommands[0].split(" ")[1];
    let tmpDir;
    if (newDirectory.startsWith("..")) {
      return (
        "Directory not allowed. You can only access files inside the project directory: " +
        originalWorkingDirectory
      );
    } else {
      tmpDir = path.join(workingDirectory, newDirectory);
    }
    //verify if tmpDir is inside the originalWorkingDirectory
    if (tmpDir.startsWith(originalWorkingDirectory)) {
      workingDirectory = tmpDir;
      if (debug)
        console.log("Changed working directory to " + workingDirectory);
      //remove the first command
      subcommands.shift();
    } else {
      if (debug)
        console.log(
          "Directory not allowed. You can only access files inside the project directory: " +
            originalWorkingDirectory
        );
      return (
        "Directory not allowed. You can only access files inside the project directory: " +
        originalWorkingDirectory
      );
    }
    if (fs.existsSync(tmpDir)) {
      workingDirectory = tmpDir;
    } else {
      return "Directory not found";
    }
  }

  command = subcommands.join("&&");

  return new Promise(async (resolve, reject) => {
    function outputCallback(id, output, outputError) {
      if (debug)
        console.log("[" + id + "] Trigger output callback on process " + id);
      let finalResult = output + "\n";
      if (outputError && outputError.length > 0) {
        finalResult += "stderr: " + outputError;
      }
      if (debug) console.log("[" + id + "] TERMINAL RESULTS:\n" + finalResult);
      resolve("Process with pid " + id + " TERMINAL RESULTS:\n" + finalResult);
    }

    function exitCallback(id, code, output, outputError) {
      if (debug)
        console.log("[" + id + "] TERMINATED: Command exited with code", code);
      //remove from running commands
      const index = runningCommands.findIndex((c) => c.id === id);
      if (index !== -1) {
        runningCommands.splice(index, 1);
      }
      output += "\nProcess with pid " + id + " exited with code " + code;
      outputCallback(id, output, outputError);
    }

    //always terminate the process before running a new command
    let currentProcess = runningCommands.find(
      (c) => c.command.main == isMainCommandToRunTheSoftware
    );

    //main process exists, kill it before running a new one
    if (currentProcess) {
      if (debug)
        console.log("Killing current process before running a new one");
      await currentProcess.command.kill();
      //remove from running commands
      const index = runningCommands.indexOf(currentProcess);
      runningCommands.splice(index, 1);
    }

    /*if (runningCommands.length > 2) {
        if (debug) console.log("There are already 2 commands running");
        resolve(
          "Max parallel processes reached. Theere are already 2 commands running with PIDs: " +
            runningCommands.map((el) => el.id).join(", ") +
            ". Exit one of them to run a new command."
        );
        return;
      } else {*/
    //Lets create a new command
    let childId = ChildCommand.generateId();
    if (debug) console.log("Running new command with id " + childId);
    let childCommand = new ChildCommand(
      childId,
      command,
      outputCallback,
      exitCallback,
      workingDirectory,
      isMainCommandToRunTheSoftware,
      debug
    );
    runningCommands.push({
      id: childId,
      main: isMainCommandToRunTheSoftware,
      command: childCommand,
    });
    //}
  });
  //gather output from command and return it after 3 seconds
  /*let promise = new Promise((resolve, reject) => {
      exec(command.command, (error, stdout, stderr) => {
        if (error) {
          console.error(`exec error: ${error}`);
          reject(error);
        }
        
        console.log(`stdout: ${stdout}`);
        //console.error(`stderr: ${stderr}`);
        resolve("TERMINAL RESULTS: " + stdout + "\n" + "Error: " + stderr);
      });
    });
    let result = await promise;*/
}
//interact with the terminal
async function interactWithRunningTerminal({ stdin, pid }) {
  if (debug) console.log("Interacting with terminal stdin " + stdin);
  if (runningCommands.length > 0) {
    let runningTerminal = runningCommands.find((c) => c.id === pid);
    if (stdin === "exit") {
      await runningTerminal.command.kill();
      //remove from running commands
      const index = runningCommands.indexOf(runningTerminal);
      runningCommands.splice(index, 1);
      return "Terminal closed";
    }
    /*
if (pid && pid.length > 0) {
      //we already have a command running
      let runningTerminal = runningCommands.find((c) => c.id === pid);
      if (!runningTerminal) {
        if (debug)
          console.log(
            "[" + pid + "] ERROR: Process with pid " + pid + " not found"
          );
        resolve(
          "Process with pid " +
            pid +
            " not found\nCureently running processes: " +
            runningCommands.map((el) => el.id).join(", ") +
            "\nPlease run the command again with the correct pid."
        );
      } else {
        //set the callbacks
        runningTerminal.command.setCallbacks(outputCallback, exitCallback);
        if (command === "exit") {
          await runningTerminal.command.kill();
          //remove from running commands
          const index = runningCommands.indexOf(runningTerminal);
          runningCommands.splice(index, 1);
          if (debug)
            console.log(
              "[" + id + "] INFO Terminating process with pid " + pid
            );
        } else {
          if (debug) console.log("[" + id + "] INFO Running " + command);
          //TODO give a callback to the command to send the output?
          runningTerminal.command.input(command);
        }
      }
    } 
    */
    return new Promise(async (resolve, reject) => {
      function outputCallback(id, output, outputError) {
        if (debug)
          console.log("[" + id + "] Trigger output callback on process " + id);
        let finalResult = output + "\n";
        if (outputError && outputError.length > 0) {
          finalResult += "stderr: " + outputError;
        }
        if (debug)
          console.log("[" + id + "] TERMINAL RESULTS:\n" + finalResult);
        resolve("TERMINAL RESULTS:\n" + finalResult);
      }

      function exitCallback(id, code, output, outputError) {
        if (debug)
          console.log(
            "[" + id + "] TERMINATED: Command exited with code",
            code
          );
        //remove from running commands
        const index = runningCommands.findIndex((c) => c.id === id);
        if (index !== -1) {
          runningCommands.splice(index, 1);
        }
        output += "\nProcess with pid " + id + " exited with code " + code;
        outputCallback(id, output, outputError);
      }
      runningTerminal.command.setCallbacks(outputCallback, exitCallback);
      await runningTerminal.command.input(stdin);
    });
  } else {
    return "No terminal running";
  }
}

//open website and get its content
async function openWebsite({ url }) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(url);
  //const dom = await page.content();
  //extract the text from the html
  let pageText = await page.$eval("*", (el) => {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNode(el);
    selection.removeAllRanges();
    selection.addRange(range);
    return window.getSelection().toString();
  });
  await browser.close();
  return pageText;
}

//open website with console results and get its content
async function openWebsiteWithConsole({ url }) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  let pageConsole = "";
  page.on("console", (message) => {
    const type = message.type().substr(0, 3).toUpperCase();
    if (debug) console.log("BROWSER CONSOLE: " + `${type} ${message.text()}`);
    let newData = `${type} ${message.text()}\n`;
    //only apped if it is not already in the pageConsole
    if (!pageConsole.endsWith(newData)) {
      pageConsole += newData;
    }
  });
  await page.goto(url);
  //const dom = await page.content();
  //extract the text from the html
  let pageText = await page.$eval("*", (el) => {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNode(el);
    selection.removeAllRanges();
    selection.addRange(range);
    return window.getSelection().toString();
  });
  //get console logs after 30 seconds
  await new Promise((resolve) => setTimeout(resolve, 30000));
  await browser.close();
  return pageText + "\n\n" + "CONSOLE RESULTS:\n" + pageConsole;
}

//download sound effect (from BBC sound effects)
async function downloadSoundEffectMp3({ searchQuery, destinationFilePath }) {
  //search for sound effect (POST https://sound-effects-api.bbcrewind.co.uk/api/sfx/search)

  //check destinationFilePath
  if (debug) console.log("Destination file path", destinationFilePath);
  let absolutePath = path.join(workingDirectory, destinationFilePath);
  absolutePath = autoFixPath(absolutePath);

  let payload = {
    criteria: {
      query: searchQuery,
      sortBy: "relevance",
      from: 0,
      size: 10,
      categories: null,
    },
  };
  const searchResults = await axios.post(
    "https://sound-effects-api.bbcrewind.co.uk/api/sfx/search",
    payload
  );
  let results = searchResults.data.results;
  if (debug) console.log("BBC Sounds search results: ", results);
  if (results.length > 0) {
    //download the first sound effect
    try {
      let firstSoundEffect = results[0];
      //download sound effect (GET https://sound-effects-media.bbcrewind.co.uk/mp3/{id}).mp3
      const soundEffect = await axios.get(
        "https://sound-effects-media.bbcrewind.co.uk/mp3/" +
          firstSoundEffect.id +
          ".mp3",
        { responseType: "arraybuffer" }
      );
      //save sound effect to file
      fs.writeFileSync(absolutePath, soundEffect.data, {
        recursive: true, //create folders if they don't exist
      });
      return "Sound effect downloaded";
    } catch (err) {
      console.error(err);
      return "Error downloading sound effect";
    }
  } else {
    return "Sound effect not found";
  }
}

//download image from Unsplash
async function downloadImage({ searchQuery, destinationFilePath }) {
  //verify if we have an Unsplash key
  if (unsplashAccessKey == null) {
    //verify if we have an Unsplash kek in the home directory
    if (fs.existsSync(homedir + "/.unsplash")) {
      let unsplashRaw = fs.readFileSync(homedir + "/.unsplash").toString();
      unsplashAccessKey = JSON.parse(unsplashRaw).accessKey;
    } else {
      console.log(
        "To be able to search and download images automatically, you need an Unsplash access key. Go to https://unsplash.com/developers to get your key."
      );
      let answrs = await inquirer.prompt([
        {
          type: "input",
          name: "accessKey",
          message: "Enter your Unsplash access key:",
          validate: function (value) {
            if (value.length) {
              return true;
            } else {
              return "Please enter your Unsplash access key.";
            }
          },
        },
      ]);
      unsplashAccessKey = answrs.accessKey;
      fs.writeFileSync(
        homedir + "/.unsplash",
        JSON.stringify({
          accessKey: unsplashAccessKey,
        })
      );
    }
  }
  if (debug) console.log("Destination file path", destinationFilePath);
  let absolutePath = path.join(workingDirectory, destinationFilePath);
  absolutePath = autoFixPath(absolutePath);
  //search for image (GET https://api.unsplash.com/search/photos)
  const response = await axios.get("https://api.unsplash.com/search/photos", {
    params: {
      query: searchQuery,
      client_id: unsplashAccessKey,
    },
  });
  let results = response.data.results;
  if (results.length > 0) {
    //download the first image
    try {
      let firstImage = results[0];
      if (debug) console.log("First image: ", firstImage);
      //download image
      const image = await axios.get(firstImage.urls.regular, {
        responseType: "arraybuffer",
      });
      //save image to file
      fs.writeFileSync(absolutePath, image.data);
      return "Image downloaded to " + destinationFilePath;
    } catch (err) {
      console.error(err);
      return "Error downloading image";
    }
  } else {
    return "Image not found with query: " + searchQuery;
  }
}

async function stepCompleted() {
  if (debug) console.log("Step completed");
  //currentStep++;
  if (runner) {
    runner.abort();
  }
}

async function commitAgent() {
  time.commit = new Date();
  agentMessages = [] //reset messages
  agentMessages.unshift({
    role: "system",
    content:
      "You are a software developer. Your goal is to generate a commit message for this project. Use ```git add .``` and ```git --no-pager diff --minimal --unified=0``` commands to check the changes that happened in this project. The machine you are running the software has the OS " +
      systemInfo +
      ". You can run terminal commands using the function runCommand. Don't explain the commands, just use them directly. Use them to interact with the system to achieve your goal. These are the current files in the project folder:\n" +
      folderFiles.join("\n") +
      "\nIf you see TERMINAL RESULTS these are the results of any command you run in the terminal. In the end, show the proposed commit message and ask the user if he accepts it before using ```git commit -m <msg>``` to commit the changes.",
  });
  agentMessages.push({
    role: "user",
    content: "Generate a commit message for this project.",
  });
  await runAgent("commit", agentMessages, [], false);
}

async function runAgent(
  role = null,
  messages = [],
  toolsAvailable = [],
  printLastMessage = true
) {
  //create a copy of messages
  messages = JSON.parse(JSON.stringify(messages));
  try {
    openAiClient = new OpenAI({
      apiKey: openai,
    });
  } catch (e) {
    console.error(e);
    console.log(
      "A valid OpenAI key is required to use this service. Go to https://platform.openai.com/account/api-keys to get your key."
    );
    process.exit(0);
  }

  //reset
  numAttempts = 0;
  let finalContent;
  let allTools = [
    {
      type: "function",
      function: {
        name: "openFile",
        description: "Open the contens of a file",
        parse: JSON.parse,
        function: openFile,
        parameters: {
          type: "object",
          properties: {
            file: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "createFileInCurrentDirectory",
        description:
          "Create a file in the current directory with the given content and name",
        parse: JSON.parse,
        function: createFileInCurrentDirectory,
        parameters: {
          type: "object",
          properties: {
            fileName: { type: "string" },
            content: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "deleteFile",
        description: "Delete a file in the current directory",
        parse: JSON.parse,
        function: deleteFile,
        parameters: {
          type: "object",
          properties: {
            file: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "renameFile",
        description:
          "Rename a file in the current directory using the current file path and the new file path. The file path should be relative to the working directory.",
        parse: JSON.parse,
        function: renameFile,
        parameters: {
          type: "object",
          properties: {
            oldFilePath: { type: "string" },
            newFilePath: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "replaceContentFile",
        description: "Replace the content of a file in the current directory",
        parse: JSON.parse,
        function: replaceContentFile,
        parameters: {
          type: "object",
          properties: {
            file: { type: "string" },
            content: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "appendContentToFile",
        description:
          "Append content to the end of a file in the current directory",
        parse: JSON.parse,
        function: appendContentToFile,
        parameters: {
          type: "object",
          properties: {
            file: { type: "string" },
            content: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "runCommand",
        description:
          "This function runs the provided command in the terminal. isMainCommandToRunTheSoftware should be true if the command is the main command to run the software. If the command is not the main command, the previous command will be terminated before running the new command.",
        parse: JSON.parse,
        function: runCommand,
        parameters: {
          type: "object",
          properties: {
            command: { type: "string" },
            isMainCommandToRunTheSoftware: { type: "boolean" },
          },
        },
      },
    },
    /*{
      type: "function",
      function: {
        name: "interactWithRunningTerminal",
        description:
          "Use this function to interact with the stdin of a running terminal selected by using its pid (process id). If needed, codify the keyboard keys in ASCII for non alphanumeric keys in the stdin.",
        parse: JSON.parse,
        function: interactWithRunningTerminal,
        parameters: {
          type: "object",
          properties: {
            stdin: { type: "string" },
            pid: { type: "string" },
          },
        },
      },
    },*/
    {
      type: "function",
      function: {
        name: "openWebsite",
        description: "Open a website and get its DOM tree",
        parse: JSON.parse,
        function: openWebsite,
        parameters: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "saveSoftwarePlanStep",
        description: "Save the plan step of the software plan",
        parse: JSON.parse,
        function: saveSoftwarePlanStep,
        parameters: {
          type: "object",
          properties: {
            stepNumber: { type: "number" },
            stepData: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "stepCompleted",
        description:
          "Call this function when you finish the implementation of the current step",
        parse: JSON.parse,
        function: stepCompleted,
        parameters: {
          type: "object",
          properties: {},
        },
      },
    },
    {
      type: "function",
      function: {
        name: "specificationsReady",
        description:
          "Call this function with the full specifications if the user agrees with the specifications to be analised and implemented.",
        parse: JSON.parse,
        function: specificationsReady,
        parameters: {
          type: "object",
          properties: {
            softwareSpecifications: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "softwarePlanReady",
        description:
          "Call this function with the full software plan if the user agrees with the software plan to be implemented.",
        parse: JSON.parse,
        function: softwarePlanReady,
        parameters: {
          type: "object",
          properties: {
            softwarePlan: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "openWebsiteWithConsole",
        description:
          "Open a website and get its DOM tree content and console logs after 30 seconds",
        parse: JSON.parse,
        function: openWebsiteWithConsole,
        parameters: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "downloadSoundEffectMp3",
        description: "Download a sound effect in mp3 format",
        parse: JSON.parse,
        function: downloadSoundEffectMp3,
        parameters: {
          type: "object",
          properties: {
            searchQuery: { type: "string" },
            destinationFilePath: { type: "string" },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "downloadImage",
        description:
          "Download an image to a destination path inside the working directory based on a search query",
        parse: JSON.parse,
        function: downloadImage,
        parameters: {
          type: "object",
          properties: {
            searchQuery: { type: "string" },
            destinationFilePath: { type: "string" },
          },
        },
      },
    },
    /*{
      type: "function",
      function: {
        name: "generateImage",
        description:
          "Generate an image based on a prompt and download it to the filepath provided",
        parse: JSON.parse,
        function: generateImage,
        parameters: {
          type: "object",
          properties: {
            prompt: { type: "string" },
            filePath: { type: "string" },
          },
        },
      },
    },*/
    {
      type: "function",
      function: {
        name: "createFolder",
        description: "Create a folder in the current directory",
        parse: JSON.parse,
        function: createFolder,
        parameters: {
          type: "object",
          properties: {
            folderName: { type: "string" },
          },
        },
      },
    },
  ];

  let coderRoles = ["coder", "evaluator", "tester", "runner"];

  let selectedTools =
    toolsAvailable == null
      ? [] :
      role == "commit" ?
        allTools.filter((tool) => tool.function.name == "runCommand" || tool.function.name == "openFile") 
      : toolsAvailable && toolsAvailable.length > 0
      ? allTools.filter((tool) => toolsAvailable.includes(tool.function.name))
      : coderRoles.includes(role)
      ? allTools.filter(
          (tool) =>
            tool.function.name != "softwarePlanReady" &&
            tool.function.name != "specificationsReady" &&
            tool.function.name != "saveSoftwarePlanStep" &&
            tool.function.name != "openWebsite"
        )
      : allTools;
  if (debug)
    console.log(
      "Selected tools: ",
      selectedTools.map((tool) => tool.function.name)
    );
  let lastMessage = "";
  spinner.start("Running AI...");
  maxAttempts = 1; //role == "runner" ? 3 : 1;
  let chatCompletions =
    role == "coder" ||
    role == "evaluator" ||
    role == "runner" ||
    role == "planExtractor" ||
    role == "commit"
      ? 50
      : 10;
  while (numAttempts < maxAttempts) {
    if (debug) console.log("Attempt: ", numAttempts);
    try {
      runner = await openAiClient.beta.chat.completions
        .runTools(
          {
            model: "gpt-4o",
            messages: messages,
            tools: selectedTools,
            max_tokens: 4000,
            temperature: role == "planExtractor" ? 0.0 : 0.5,
            //temperature: 0.5,
            tool_choice:
              role == "coder" || role == "evaluator" || role == "tester"
                ? "required"
                : "auto",
          },
          { maxChatCompletions: chatCompletions }
        )
        .on("content", (diff) => {
          //console.log("diff", diff);
          if (diff.content && diff.role == "assistant") {
            //spinner.stop();
            console.log("[⏺︎_] " + diff.content);
            agentMessages.push({
              role: diff.role,
              content: diff.content,
            });
            //spinner.start("Running AI...");
          }
        })
        .on("message", (msg) => {
          /*if (msg.content && msg.role == "assistant") {
            //spinner.stop();
            console.log("[⏺︎_] " + msg.content);
            agentMessages.push({
              role: msg.role,
              content: msg.content,
            });
            //spinner.start("Running AI...");
          }*/
        })
        .on("functionCall", (functionCall) => {
          let ignoreFunctions = [
            "specificationsReady",
            "softwarePlanReady",
            "askUserForInput",
            "stepCompleted",
            "saveSoftwarePlanStep",
          ];
          if (debug) console.log("calling ", functionCall);
          let funcargs = JSON.parse(functionCall.arguments);
          if (functionCall.name == "createFileInCurrentDirectory") {
            if (funcargs) {
              spinner.info("Creating the file " + funcargs.fileName);
            } else {
              spinner.info("Creating a file");
            }
          }else if(functionCall.name == "openWebsiteWithConsole"){
            if (funcargs) {
              spinner.info("Opening the website " + funcargs.url);
            } else {
              spinner.info("Opening a website");
            }
          } else if (functionCall.name == "deleteFile") {
            if (funcargs) {
              spinner.info("Deleting the file " + funcargs.file);
            } else {
              spinner.info("Deleting a file");
            }
          } else if (functionCall.name == "renameFile") {
            if (funcargs) {
              spinner.info(
                "Renaming the file " + funcargs.file + " to " + funcargs.newName
              );
            } else {
              spinner.info("Renaming a file");
            }
          } else if (functionCall.name == "replaceContentFile") {
            if (funcargs) {
              spinner.info("Writting content to the file " + funcargs.file);
            } else {
              spinner.info("Writting content to a file");
            }
          } else if (functionCall.name == "runCommand") {
            if (funcargs) {
              spinner.info("Running the command " + funcargs.command);
            } else {
              spinner.info("Running a command");
            }
          } else if (functionCall.name == "openWebsite") {
            if (funcargs) {
              spinner.info("Opening the website " + funcargs.url);
            } else {
              spinner.info("Opening a website");
            }
          } else if (functionCall.name == "createFolder") {
            if (funcargs) {
              spinner.info("Creating the folder " + funcargs.folderName);
            } else {
              spinner.info("Creating a folder");
            }
          } else if (functionCall.name == "openFile") {
            if (funcargs) {
              spinner.info("Opening the file " + funcargs.file);
            } else {
              spinner.info("Opening a file");
            }
          } else if (ignoreFunctions.includes(functionCall.name)) {
            //do nothing
          } else {
            spinner.info(
              "Calling " +
                functionCall.name +
                " with parameters: " +
                JSON.stringify(funcargs)
            );
          }
        })
        .on("error", (error) => {
          //console.error("Error: ", );
          if (error.error && error.error.message) {
            if (debug) console.log("Error: ", error.error.message);
            spinner.fail("OpenAI error: " + error.error.message);
          } else if (error.message) {
            if (debug) console.log("Error: ", error.message);
            spinner.fail("OpenAI error: " + error.message);
          } else {
            if (debug) console.log("Error: ", error);
            spinner.fail("OpenAI error: " + error);
          }
        })
        .on("abort", (abort) => {
          if (debug) console.log("Abort: ", abort);
        })
        .on("exit", (exit) => {
          if (debug) console.log("Exit: ", exit);
        })
        .on("finalChatCompletion", (finalContent) => {
          //console.log("finalChatCompletion", finalContent);
        });
    } catch (e) {
      if (debug) console.error(e);
      spinner.fail("OpenAI error: " + e.error.message);
      //console.log("OpenAI error: " + e.error.message);
    }
    /*.on("functionCallResult", (functionCallResult) =>
        console.log("functionCallResult", functionCallResult)
      );*/
    //.on("content", (diff) => process.stdout.write(diff));

    try {
      finalContent = await runner.finalChatCompletion();
      lastMessage = finalContent.choices[0].message.content;
      //console.log("Final content: ", lastMessage);
      if (lastMessage && printLastMessage) {
        console.log("[⏺︎_] " + lastMessage);
        agentMessages.push({
          role: finalContent.choices[0].message.role,
          content: lastMessage,
        });
      }
      if (finalContent) {
        outputTokens += finalContent.usage.completion_tokens;
        inputTokens += finalContent.usage.prompt_tokens;
      }
    } catch (e) {
      if (debug) console.error(e);
      /*if (e.error && e.error.message) {
        spinner.fail("OpenAI error: " + e.error.message);
      } else if (e.error) {
        spinner.fail("OpenAI error: " + e.error);
      }
      console.log("OpenAI error: ", e);*/
      //process.exit(0);
    }
    if (role != "coder") {
      //if is not a coder, break the loop after the first attempt
      break;
    }
    //conversationMemory = runner.messages;
    numAttempts++;
  }
  if (folderFiles.length > 0 && debug) {
    if (debug) console.log("=== FINAL FOLDER ESTRUCTURE ===");
    if (debug) console.log(folderFiles);
  }
  spinner.stop();
  if (lastMessage && lastMessage.length > 0) {
    return lastMessage;
  } else {
    if (debug) console.log("No content generated");
    return null;
  }
}

async function generateCode() {
  time.coder = new Date();
  readFolderFiles();

  //delete all system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");
  //get only last 5 messages
  agentMessages = agentMessages.slice(-5);

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a software developer. You received a step of a bigger implementation plan. Your goal is to implement only this step. The machine you are running the software has the OS " +
      systemInfo +
      ". You have a list of files and folders in the current directory. You have access to commands that open, create, delete, rename, replace content of a file, run a terminal command, and open the contents of a website. Don't explain the commands, just use them directly. Use them to interact with the files and the system to achieve your goal. These are the current files and folders in the root directory:\n" +
      folderFiles.join("\n") +
      "\nRead the current files before changing them. When needed, use environment variables inside an .env file to store any keys. Don't forget to run any commands to install dependecies. Initiate the project using terminal commands before writing any code. If you see TERMINAL RESULTS, verify if the command was successful or if you need to do changes to the code to make it successfully. When manipulating files always use the relative path in relation to the root folder of the project. If you don't know how to implement, do not invent, ask the user for a website with the documentation where you can get the information you need to implement. Verify that you integrate all the files and code needed for this step of the implementation plan. Do not use placeholders, implement the required code. Do not create empty files, always add the necessary content. Do not try to use git commit, any repository opperations will be done later. When done call stepCompleted function.",
  });

  if (debug) console.log("CONVERSATION MEMORY ===== ");
  if (debug) console.log(agentMessages);
  return await runAgent("coder", agentMessages, []);
}

async function planExtractor() {
  readFolderFiles();
  //delete all system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");
  //get only last 5 messages
  agentMessages = agentMessages.slice(-10);

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a software developer. You received a plan to implement the software and your goal is to extract the plan from the conversation.",
  });

  agentMessages.push({
    role: "user",
    content:
      "Extract the software plan from the conversation, step by step. Extract each step and save it to a file using the saveSoftwarePlanStep function. The step 0 should give some context about the implementation plan and it will be appended to all the other steps. These steps will be provided to a software developer to implement the software.",
  });

  if (debug) console.log("CONVERSATION MEMORY ===== ");
  if (debug) console.log(agentMessages);
  let planResult = await runAgent(
    "planExtractor",
    agentMessages,
    ["saveSoftwarePlanStep"],
    false
  );
  console.log("Plan result json: ", planResult);
}

async function evaluator() {
  readFolderFiles();
  //delete all system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");
  //let hasReadme = false;
  //verify if we have a readme file
  /*if (folderFiles.includes("README.md")) {
    console.log("README.md file found");
    hasReadme = true;
  }*/

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a senior software developer. You are resposible to evaluate the work from another developer and respond with ```Result: PASS``` if the software written implements all the features in the software plan. Verify if all the functions and methods are implemented and without any placeholders. If your evaluation fails or if you see any problems with the code write ```Result: NOT_PASS``` and provide suggestions to be given to the software developer so it can iterate again. You have a list of files and folders in the current directory and you can call commands that open and read any files of the folder. These are the files and folders in the current directory:\n" +
      folderFiles.join("\n") +
      "\nWhen manipulating or opening files always use the relative path in relation to the root folder of the project. Verify if the developer wrote comments in the code and if we have an exaustive README.md file with instructions on how to run the code and examples of payload if needed. If there is a package.json file, verify if it includes the commands to run the code inside. Verify if there is no placeholders and if the code is fully implemented. Do not try to use git commit, any repository opperations will be done later. Ignore any file that is not related to the software implementation and that is not code (assets, media, images, sound or music).",
  });
  /*
"You are a senior software developer. You are resposible to evaluate the work from another developer and respond with ```Result: PASS``` if the software written works and matches the software plan provided. If it fails or it is not correct write ```Result: NOT_PASS``` and provide with suggestions to be given to the software developer so it can iterate again. You have a list of files in the current directory and you can call commands that open and read any files of the folder. These are the files in the current directory separated by commas: " +
      folderFiles.join(", ") +
      ". When manipulating or opening files always use the relative path in relation to the root folder of the project. Verify if the developer wrote comments in the code and if we have an exaustive README.md file with instructions on how to run the code and examples of payload if needed. If there is a package.json file, verify if it includes the commands to run the code inside. Verify if there is no placeholder and if the code is fully implemented and verify if runs successfully without any errors.",
    //"This is the software implementation plan:\n" + softwarePlan,
  */
  return await runAgent("evaluator", agentMessages, [
    "openFile",
    "openWebsite",
  ]);
}

async function softwarerunner() {
  readFolderFiles();
  //delete all system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");
  //let hasReadme = false;
  //verify if we have a readme file
  /*if (folderFiles.includes("README.md")) {
    console.log("README.md file found");
    hasReadme = true;
  }*/

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a senior software developer. Run the software provided and check for any runtime errors. The machine you are running the software has the OS " +
      systemInfo +
      ". If there are no errors after running the software respond with ```Result: PASS```. If you find runtime errors edit the software to fix them acording to the software implementation plan. If you cannot fix the errors reply with ```Result: NOT_PASS```. You have a list of files and folders in the current directory and you can call commands that open and read any files of the folder. These are the current files and folders in the root directory:\n" +
      folderFiles.join("\n") +
      "\nWhen manipulating or opening files always use the relative path in relation to the root folder of the project. To start the software you might find the instructions in the README.md file if provided. If its a web project, run first the backend and then try to open and navidate the frontend in the browser.",
  });
  /*
"You are a senior software developer. You are resposible to evaluate the work from another developer and respond with ```Result: PASS``` if the software written works and matches the software plan provided. If it fails or it is not correct write ```Result: NOT_PASS``` and provide with suggestions to be given to the software developer so it can iterate again. You have a list of files in the current directory and you can call commands that open and read any files of the folder. These are the files in the current directory separated by commas: " +
      folderFiles.join(", ") +
      ". When manipulating or opening files always use the relative path in relation to the root folder of the project. Verify if the developer wrote comments in the code and if we have an exaustive README.md file with instructions on how to run the code and examples of payload if needed. If there is a package.json file, verify if it includes the commands to run the code inside. Verify if there is no placeholder and if the code is fully implemented and verify if runs successfully without any errors.",
    //"This is the software implementation plan:\n" + softwarePlan,
  */
  return await runAgent("runner", agentMessages, []);
}

async function specificator(currentUserPrompt) {
  /*
  ADITIONAL KNOWLEDGE:
  */
  const additionalKnowledge =
    "If the requested project is one of this list, use one of the following commands to start the project: \n" +
    'VueJS project: yes "" | npm create vue@latest <project-name> \n' +
    "Nuxt project: npx nuxi@latest init <project-name> \n" +
    'React project with NextJS: yes "" | npx create-next-app@latest <project-name> \n' +
    "React project with Remix: npx create-remix@latest ./ --template remix-run/grunge-stack \n" +
    "React project with Gatsby: npx create-gatsby \n" +
    "React native: npx create-expo-app <project-name> \n";
  ("To install a new package in a Flutter app: flutter pub add <package-name> \n");

  time.specifications = new Date();
  readFolderFiles();
  agentMessages = [
    {
      role: "system",
      content:
        "You are a software architect, part of a team of software development. You receive the implementation task from the user and your job is to create the specification: current vs proposed with file refences. The machine you are running the software has the OS " +
        systemInfo +
        ". You have a list of files and folders in the current directory and you have access to commands that open any files in the folder and that open any website you want. These are the files and folders in the current directory separated by commas:\n" +
        folderFiles.join("\n") +
        "\nIf you don't know how to implement something, ask the user for guidance (for example to provide a website with the documentation). If the user provides a website, read it before starting planning. Do not implement the software. In the specifications you should mention the creation or edition of a README.md file with instructions in how to run the software. Ask the developer to add an .gitignore file adapted to this project. Do not include any code in the specifications. " +
        additionalKnowledge +
        "When referencing files always use the relative path in relation to the root folder of the project. Don't use the cd command alone. If needed use it with other commands to be able to run a command directly from the root folder of the project. Generate the specifications in markdown language. When you are done, ask the user if he agrees with the specification and call the function `specificationsReady` with the full software specifications to continue to the software planning phase (do not tell the user that you are going to call specificationsReady).",
    },
    {
      role: "user",
      content: currentUserPrompt,
    },
  ];
  let lastMessage, response;
  while (!hasSoftwareSpecifications) {
    await runAgent("specificator", agentMessages, [
      "openFile",
      "openWebsite",
      "specificationsReady",
    ]);
    //console.log("[⏺︎_] " + lastMessage);
    if (hasSoftwareSpecifications) {
      return;
    }
    /*conversationMemory.push({
      role: "assistant",
      content: lastMessage,
    });*/
    response = await inquirer.prompt([
      {
        type: "input",
        name: "user",
        message: "You:",
      },
    ]);
    if (response && response.user && response.user.length > 0) {
      agentMessages.push({
        role: "user",
        content: response.user,
      });
    } else {
      exit();
    }
  }
}

//Goal is to generate a plan to implement the software file by file
async function planner() {
  readFolderFiles();
  time.plan = new Date();
  //remove system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");
  //get only last 7 messages
  agentMessages = agentMessages.slice(-7);

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a software tech lead, part of a team of software development. You received the specification and your job is to create a plan step by step of what should be done. The project will be implemented in a machine with the OS " +
      systemInfo +
      "\nInclude which files should be created or edited. Each step should be incremental and use what was done in the previous steps. If there is a dependency on another file, create the other file first before using it as a dependency. For each step, describe a list of tasks needed to be accomplished to achieve the goals of the specification.\n" +
      "You have a list of files and folders in the current directory and you have access to commands that open any files in the folder and that open any website you want. These are the files and folders in the current directory separated by commas:\n" +
      folderFiles.join("\n") +
      "\nWhen referencing files always use the relative path in relation to the root folder of the project. Don't use the cd command alone. If needed use it with other commands to be able to run a command directly from the root folder of the project. Don't propose solutions, create the plan with those solutions. Generate the plan in markdown language. When you are done, ask the user if he agrees with the plan and call the function `softwarePlanReady` with the full software plan to continue to the software implementation phase (do not say to the user that you will call softwarePlanReady function).",
  });

  agentMessages.push({
    role: "user",
    content:
      "Create the plan to implement the software based on the specification provided.",
  });

  if (debug) console.log("CONVERSATION MEMORY ===== ");
  if (debug) console.log(agentMessages);

  let lastMessage, response;
  while (!hasSoftwarePlan) {
    await runAgent("planner", agentMessages, [
      "openFile",
      "openWebsite",
      "softwarePlanReady",
    ]);
    //console.log("[⏺︎_] " + lastMessage);
    if (hasSoftwarePlan) {
      return;
    }
    response = await inquirer.prompt([
      {
        type: "input",
        name: "user",
        message: "You:",
      },
    ]);
    if (response && response.user && response.user.length > 0) {
      agentMessages.push({
        role: "user",
        content: response.user,
      });
    } else {
      exit();
    }
  }
}

//"Use environment variables for any keys you need. Don't forget to ask to create the .env file if needed. If you read any documentation or website, explain how to use a specific software so the developer can use it. Don't forget to ask to run any commands to install dependecies and that they should run the code generated to test if it works. All dependencies used must be up to date, ask the developer to upgrade if needed. Ask to initiate the project using terminal commands before writing any code. When manipulating files always use the relative path in relation to the root folder of the project.  In the end, ask the developer to write an exaustive README.md file in the root of the project with instructions on how to run the code and examples of payload if needed. If there is the need to generate a package.json file, make sure to include the commands to run the code inside. This plan will be given to the developers to implement. Output a JSON with an array of the features and plans to implement them."

async function tester() {
  readFolderFiles();
  let hasReadme = false;
  time.tester = new Date();
  //verify if we have a readme file
  if (folderFiles.includes("README.md")) {
    if (debug) console.log("README.md file found");
    hasReadme = true;
  }

  let promptTester = "";

  if (hasReadme) {
    //read the readme file
    let readme = fs.readFileSync("README.md", "utf8");
    if (debug) console.log("README.md content:", readme);
    promptTester =
      "Test all code provided in the current folder. The machine you are running the software has the OS " +
      systemInfo +
      ". Use the README.md file to understand how to run the software. Go file by file and write tests for each function or piece of code in a separate folder. Run those testes and check if they are sucessful or not. If you see any issues, try to fix them and test them again. If its an web API, use Curl to test each route. Examples of payload for each route should be found in the README.md file. Content of the README.md file:\n" +
      readme +
      "\nIn the end, generate a TESTS.md file with all the tests you ran, the results and if all tests passed or failed. Execute all the tests without asking the user for permission.";
  } else {
    promptTester =
      "Test all code provided in the current folder. Go file by file and write tests for each function or piece of code in a separate folder. Run those testes and check if they are sucessful or not. If you see any issues, try to fix them and test them again. If its an web API, use Curl to test each route. In the end, generate a TESTS.md file with all the tests you ran, the results and if all tests passed or failed. Execute all the tests without asking the user for permission.";
  }

  //remove system message if it exists
  agentMessages = agentMessages.filter((msg) => msg.role != "system");

  //add new system message
  agentMessages.unshift({
    role: "system",
    content:
      "You are a software tester responsible for the quality of the software developed. You have a list of files and folders in the current directory. You have access to commands that open, create, delete, rename, replace content of a file, run a terminal command, and open the contents of a website. Use the following tools to interact with the files and the system to achieve your goal. These are the files and folders in the current directory:\n" +
      folderFiles.join("\n") +
      "\nDon't forget to run any commands to install dependecies and try to run the code. Use Curl or Postman to test the API endpoints. If you see TERMINAL RESULTS, verify if the command was successful or if you need to do changes to the code to make it successfully. Only ask the user for variables that you do need to run the software and that you can't find in the .env file.",
  });
  agentMessages.push({
    role: "user",
    content: promptTester,
  });

  return await runAgent("tester", agentMessages, []);
}

async function createGitRepository() {
  //use commands to create a git repository
  if (isGit) {
    spinner.info("Git repository already exists");
    return;
  }
  spinner.info("Creating a git repository...");
  //use the command to create a git repository
  await runCommand({
    command: "git init",
  });
  spinner.succeed("Git repository created!");
}

let donePhases = [];
let softwareSteps = [];

function printPlanProgress() {
  let progress = Math.round((currentStep / softwareSteps.length) * 50);
  let progressBar = "";
  for (let i = 0; i < progress; i++) {
    progressBar += "█";
  }
  for (let i = progress; i < 50; i++) {
    progressBar += "░";
  }
  console.log("Progress: " + progressBar + " " + (progress * 2) + "%");
}

function setupGitignore() {
  if (
    fs.existsSync(
      path.join(originalWorkingDirectory, ".gitignore")
    )
  ) {
    let gitignoreContent = fs.readFileSync(
      path.join(originalWorkingDirectory, ".gitignore"),
      "utf8"
    );
    if (!gitignoreContent.includes(".dotdev")) {
      fs.appendFileSync(
        path.join(originalWorkingDirectory, ".gitignore"),
        ".dotdev\n"
      );
    }
  } else {
    fs.writeFileSync(path.join(originalWorkingDirectory, ".gitignore"), ".dotdev\n");
  }
}

async function runMainAgent(p) {
  if (debug) console.log("Working directory:", originalWorkingDirectory);
  if (debug) console.log("User prompt: " + p);
  time.start = new Date();
  let response;
  spinner.start();
  let skipFirstStage = false;

  //if p is empty, try to restore the previous state
  if (
    p == "" ||
    p == "runner" ||
    p == "tester" ||
    p == "evaluator" ||
    p == "coder"
  ) {
    skipFirstStage = p != "";
    //console.log("Restoring previous state...");
    spinner.info("Restoring previous state...");
    //check if we have specifications
    if (
      fs.existsSync(
        path.join(originalWorkingDirectory, ".dotdev/specifications.md")
      )
    ) {
      //console.log("Restoring specifications...");
      spinner.info("Restoring specifications...");
      let specifications = fs.readFileSync(
        path.join(originalWorkingDirectory, ".dotdev/specifications.md"),
        "utf8"
      );
      agentMessages.push({
        role: "user",
        content: "SOFTWARE SPECIFICATIONS\n" + specifications,
      });
      if (softwareSteps.length > 0) {
        spinner.succeed("Specifications restored!");
      }
      hasSoftwareSpecifications = true;
      donePhases.push("specificator");
    }
    //check if we have a software plan
    if (fs.existsSync(path.join(originalWorkingDirectory, ".dotdev/plan.md"))) {
      //console.log("Restoring software plan...");
      spinner.info("Restoring software plan...");
      let plan = fs.readFileSync(
        path.join(originalWorkingDirectory, ".dotdev/plan.md"),
        "utf8"
      );
      agentMessages.push({
        role: "user",
        content: "SOFTWARE PLAN\n" + plan,
      });
      hasSoftwarePlan = true;
      softwareSteps = await getSoftwarePlanSteps();
      if (softwareSteps.length > 0) {
        spinner.succeed("Software plan restored!");
      }
      donePhases.push("planner");
    }
  }

  if ((!p || p.length === 0) && donePhases.length == 0 && !skipFirstStage) {
    console.log("🚀 Let's create some software!");
    console.log(chalk.dim("Insert the task you want me to do"));
    console.log("");
    let answers = await inquirer.prompt([
      {
        type: "input",
        name: "prompt",
        message: "Task:",
        validate: function (value) {
          if (value.length > 0) {
            return true;
          } else {
            return "Please give me a task to do.";
          }
        },
      },
    ]);
    p = answers.prompt;
  }

  //check if we have a .git folder
  if (fs.existsSync(path.join(originalWorkingDirectory, ".git"))) {
    if (debug) console.log("Git repository found");
    //console.log("Git repository found");
    isGit = true;
    //verify if there is a gitignore with .dotdev
    setupGitignore()
  } else {
    if (debug) console.log("Git repository not found");
    //warn the user that he doesn't have a git repository to tracj changes to the code and revert if needed
    spinner.warn(
      "You don't have a git repository in this folder. We recommend you to create one to track changes to the code and revert if needed."
    );
    //ask if the user wants to create a git repository
    response = await inquirer.prompt([
      {
        type: "confirm",
        name: "response",
        message: "Do you want to create a git repository?",
      },
    ]);
    if (response.response) {
      await createGitRepository();
      setupGitignore()
      isGit = true
    }
  }

  if (!donePhases.includes("specificator") && !skipFirstStage) {
    //verify if we have a .dotdev folder
    if (fs.existsSync(path.join(originalWorkingDirectory, ".dotdev"))) {
      //delete all files inside .dotdev folder to prepare for a new task
      fs.rmSync(path.join(originalWorkingDirectory, ".dotdev"), {
        recursive: true,
      });
    }
    spinner.info("Creating specifications...");
    await specificator(p);
    donePhases.push("specificator");
  }
  if (!donePhases.includes("planner") && !skipFirstStage) {
    spinner.info("Planning code...");
    await planner();
    await planExtractor();
    //load the software plan
    spinner.succeed("Software plan created!");
    softwareSteps = await getSoftwarePlanSteps();
    donePhases.push("planner");
  }

  if (p != "runner") {
    if (debug) console.log("👨‍💻 Let's code: " + p);
    //reset conversation memory to start the implementation
    if (softwareSteps.length > 1) {
      agentMessages = [];
      let contextStep = softwareSteps[0];
      //ignore the first step
      let step = softwareSteps[currentStep];
      let currentAttempt = 0;
      let maxAttempts = 3;
      while (currentStep < softwareSteps.length) {
        //reset working directory
        workingDirectory = originalWorkingDirectory;
        step = softwareSteps[currentStep];
        spinner.stop();
        printPlanProgress();
        spinner.info(
          "Implementing software step number " + step.stepNumber + "..."
        );
        agentMessages.push({
          role: "user",
          content: contextStep.data + "\n" + step.data,
        });
        await generateCode();
        spinner.succeed("Implementation step concluded!");
        agentMessages = [];
        currentStep++;
      }
    }
  }

  //spinner.info("Evaluating code...");
  agentMessages = [];
  let fullPlan = "";
  for (let i = 0; i < softwareSteps.length; i++) {
    fullPlan += softwareSteps[i].data + "\n";
  }
  agentMessages.push({
    role: "user",
    content:
      "This is the implementation plan for the software in the current directory.\n" +
      fullPlan +
      "\nRun the provided software and fix any errors you find. The machine you are running the software has the OS " +
      systemInfo +
      ". Instructions in how to run the software are usually in the README.md file.",
  });
  /*
      let evaluationResult = await evaluator();
      let tryRun = false;
      if (evaluationResult == null || evaluationResult.includes("NOT_PASS")) {
        spinner.fail("Code did not pass formal evaluation. We will try again.");
      } else {
        spinner.succeed("Code passed formal evaluation!");
        tryRun = true;
      }*/
  //if (tryRun) {
  spinner.info("Running code...");

  let runnerResult = await softwarerunner();
  if (runnerResult == null || runnerResult.includes("NOT_PASS")) {
    spinner.fail("Code did not pass runtime evaluation. Try again later.");
    //try again the same step
  } else {
    spinner.succeed("Code passed runtime evaluation!");
  }
  //}
  /*await generateCode();
    spinner.succeed("Code generated!");
    spinner.info("Evaluating code...");
    agentMessages = [];
    let evaluationResult = await evaluator();
    let numAttempts = 0;
    let localMaxAttempts = 3;
    while (
      evaluationResult != null &&
      evaluationResult.includes("NOT_PASS") &&
      numAttempts < localMaxAttempts
    ) {
      //console.log("Code not accepted!");
      spinner.fail("Code did not pass evaluation. We will try to refactor it.");
      spinner.info("Refactoring code...");
      agentMessages.push({
        role: "user",
        content:
          "The code written didn't pass. Use the suggestions to refactor the code of the project",
      });
      await generateCode();
      agentMessages = [];
      evaluationResult = await evaluator();
      numAttempts++;
    }
    if (evaluationResult == null || evaluationResult.includes("NOT_PASS")) {
      spinner.fail("Code did not pass evaluation. Try again later.");
    } else {
      spinner.succeed("Code passed evaluation!");
    }
    agentMessages = [];
    //Use runner to test the code and fix runtime error
    spinner.info("Running code...");
    numAttempts = 0;
    evaluationResult = await runner();
    while (
      evaluationResult != null &&
      evaluationResult.includes("NOT_PASS") &&
      numAttempts < localMaxAttempts
    ) {
      //console.log("Code not accepted!");
      spinner.fail("Code did not pass evaluation. We will try to refactor it.");
      spinner.info("Refactoring code...");
      agentMessages = [];
      evaluationResult = await runner();
      numAttempts++;
    }
    if (evaluationResult == null || evaluationResult.includes("NOT_PASS")) {
      spinner.fail(
        "Sorry but we couldn't fix all the errors. Try again later."
      );
    } else {
      spinner.succeed("All errors fixes and software good to go!");
    }
    /*} else {
      spinner.fail("Software plan not accepted!");
      exit();
    }*/
  //ask the user if he wants to test the code
  response = await inquirer.prompt([
    {
      type: "confirm",
      name: "response",
      message: "Do you want us to write tests for the code?",
    },
  ]);
  if (response.response) {
    spinner.info("Testing code...");
    await tester();
    spinner.succeed("Code tested and report generated!");
  }

  //verify if there is a git repository
  /*if (isGit) {
    await commit()
  }*/
  exit()
}

main();
