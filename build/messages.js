"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MessagesClient = void 0;
const rawproto_1 = require("rawproto");
const API = require("./api");
const cheerio = require("cheerio");
const { subtle } = require('crypto').webcrypto;
const https_1 = require("./https");
const json_1 = require("./json");
const helpers_1 = require("./helpers");
const tiny_typed_emitter_1 = require("tiny-typed-emitter");
const p_queue_1 = require("p-queue");
class MessagesClient extends tiny_typed_emitter_1.TypedEmitter {
    constructor() {
        super(...arguments);
        this.queue = new p_queue_1.default({ concurrency: 1 });
        this.tempIdsSending = [];
        this.processedChunks = [];
        this.processedChunks2 = [];
        this.messageListFound = false;
        this.retryCount = 0;
        this.connected = false;
        this.UKb = function (a, c, b) {
            const d = new Uint8Array(5), e = new DataView(d.buffer);
            let f = 4;
            for (; 0 < a;)
                e.setUint8(f, a % 256),
                    a = Math.floor(a / 256),
                    f--;
            c >= b && e.setUint8(0, 1);
            return d;
        };
    }
    GetMessages(convId) {
        return __awaiter(this, void 0, void 0, function* () {
            this.emit('debug', "Triggering new messages for convid - " + convId);
            yield this.QueueFunction(() => this.TriggerGetMessages(convId));
        });
    }
    Connect() {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.Initialise();
            this.sessionData = {};
            var keys;
            keys = yield helpers_1.HelperFunctions.getKeys();
            this.sessionData.crypto_msg_enc_key = Buffer.from(keys.crypto_msg_enc_key).toString('base64');
            this.sessionData.crypto_msg_hmac = Buffer.from(keys.crypto_msg_hmac).toString('base64');
            var pubkeyexp = yield subtle.exportKey("jwk", keys.ECDSA_Keys.publicKey);
            var privkeyexp = yield subtle.exportKey("jwk", keys.ECDSA_Keys.privateKey);
            this.sessionData.crypto_pub_key = Buffer.from(JSON.stringify(pubkeyexp)).toString('base64');
            this.sessionData.crypto_pri_key = Buffer.from(JSON.stringify(privkeyexp)).toString('base64');
            var qrdata = yield this.RegisterAndGetQR(pubkeyexp, this.googleapi, keys.crypto_msg_enc_key, keys.crypto_msg_hmac);
            this.emit('qrcode', qrdata.QRLink);
            var respguid;
            yield this.GetRecMessages(qrdata.RelayData[4][5][0][1].toString('base64'), this.googleapi, (data) => __awaiter(this, void 0, void 0, function* () {
                try {
                    var allrecdata = yield this.GetRecData(data);
                    this.sessionData.pr_tachyon_auth_token = allrecdata.n64;
                    this.sessionData.bugle = allrecdata.bugle;
                    this.sessionData.bugle15 = allrecdata.bugle15;
                    this.sessionData.expiredate = this.GetdateFromExp(allrecdata.expdate);
                    respguid = allrecdata.guid;
                    return true;
                }
                catch (_a) { }
                return false;
            }));
            this.emit('sessiondata', JSON.stringify(this.sessionData));
            var httprespack = yield this.GetAckMessages(this.sessionData.pr_tachyon_auth_token, [
                respguid
            ], this.googleapi);
        });
    }
    SendMessageNoWait({ convId, senderId, tempid, text }) {
        return __awaiter(this, void 0, void 0, function* () {
            yield this.QueueFunction(() => this.TriggerSendMessage(tempid, convId, senderId, text));
        });
    }
    SendMessage(convId, senderId, text) {
        return __awaiter(this, void 0, void 0, function* () {
            var tempid = `tmp_${Math.floor(999999999999 * Math.random())}`;
            return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
                this.on('convlist', m => {
                    var messagesFound = JSON.parse(m);
                    for (var m in messagesFound) {
                        var mess = messagesFound[m];
                        if (mess.TempId == tempid) {
                            resolve(mess);
                        }
                    }
                });
                yield this.SendMessageNoWait({ convId, senderId, tempid, text });
            }));
        });
    }
    Setup(sessiond) {
        return __awaiter(this, void 0, void 0, function* () {
            this.messageListFound = false;
            this.sessionData = sessiond;
            this.queue = new p_queue_1.default({ concurrency: 1 });
            yield this.QueueFunction(() => this.Initialise());
            this.on('receivemessage', (m) => __awaiter(this, void 0, void 0, function* () {
                var data = JSON.parse(m);
                yield this.QueueFunction(() => this.ProcessNewReceiveMessage(data));
            }));
            this.on('error', (m) => __awaiter(this, void 0, void 0, function* () {
                this.connected = false;
                this.emit('debug', "Error (no retries - " + this.retryCount + ") - " + m);
                this.StopChecker();
                this.retryCount = this.retryCount + 1;
                if (this.retryCount < 5) {
                    yield this.QueueFunction(() => this.SetupPriorReceive());
                }
                else {
                    this.emit('invalidtoken', m);
                }
            }));
            yield this.QueueFunction(() => this.SetupPriorReceive());
        });
    }
    DownloadFile(guid, key) {
        return __awaiter(this, void 0, void 0, function* () {
            key = Buffer.from(key, 'base64');
            var ui = Buffer.from(this.sessionData.pr_tachyon_auth_token, 'base64');
            var uint = new Uint8Array(ui);
            var d = yield API.GetUploadRequest(uint, guid);
            var b64 = Buffer.from(d).toString('base64');
            var getresp;
            getresp = yield https_1.HttpFunctions.httpGetDownload(b64);
            getresp = new Uint8Array(getresp);
            var mp = Math.pow(2, getresp[1]);
            var id = getresp.subarray(2);
            var enckey = key;
            var cryptokey = yield subtle.importKey("raw", enckey, {
                name: "AES-GCM",
                length: enckey.length
            }, !1, ["encrypt", "decrypt"]);
            var dataresp = yield this.ProcessAll(cryptokey, id, mp, false);
            return Buffer.from(dataresp).toString('base64');
        });
    }
    ProcessAll(key, c, b, d) {
        var b;
        return __awaiter(this, void 0, void 0, function* () {
            let e;
            e = [];
            let f = 0, g = 0;
            const h = c.length;
            for (; f < h;) {
                const l = Math.min(f + b, h), n = c.slice(f, l);
                f = l;
                const r = this.UKb(g, f, h);
                var resp = yield this.decryptImage(n, r, key);
                e.push(resp);
                g++;
            }
            var a = e;
            c = 0;
            for (b of a)
                c += b.length;
            c = new Uint8Array(c);
            b = 0;
            for (const d of a)
                c.set(d, b),
                    b += d.length;
            return c;
        });
    }
    decryptImage(a, c, key) {
        return __awaiter(this, void 0, void 0, function* () {
            var b;
            b = new Uint8Array(12);
            b.set(a.subarray(0, 12));
            b = {
                name: "AES-GCM",
                iv: b,
                tagLength: 128
            };
            c && (b.additionalData = c);
            return new Uint8Array(yield subtle.decrypt(b, key, new Uint8Array(a.subarray(12))));
        });
    }
    Close() {
        return __awaiter(this, void 0, void 0, function* () {
            this.emit('closed', 'Trying to close sessions');
            for (var b of https_1.HttpFunctions.AllReqs) {
                try {
                    yield b.destroy();
                }
                catch (_a) { }
            }
        });
    }
    TriggerSendMessage(tempid, convId, senderId, text) {
        var convId, senderId;
        return __awaiter(this, void 0, void 0, function* () {
            convId = convId;
            senderId = senderId;
            var mess = {
                "message": {
                    "conversationId": convId,
                    "id": tempid,
                    "Gh": false,
                    "Lc": {
                        "0": {
                            "order": Number.MAX_SAFE_INTEGER,
                            "qc": "0",
                            "Eq": "0",
                            "type": "text",
                            "text": text
                        }
                    },
                    "senderId": senderId,
                    "status": 1,
                    "timestampMs": Date.now(),
                    "type": 1,
                    "Yh": tempid
                },
                "Ko": false
            };
            this.tempIdsSending.push(tempid);
            var sendObj = API.GetSendMessageObj(mess.message);
            var sendmess3id = yield API.GetReqId();
            yield this.SendWithMessage(sendObj, sendmess3id, this.sessionid, 3, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
        });
    }
    getQRCodeLink(qrdata, crypto_msg_enc_key, crypto_msg_hmac) {
        var qrdata;
        return __awaiter(this, void 0, void 0, function* () {
            var uint8qr = new Uint8Array(qrdata);
            qrdata = yield API.QR(uint8qr, crypto_msg_enc_key, crypto_msg_hmac);
            var buffer = Buffer.from(qrdata);
            var qrcode = buffer.toString('base64');
            return "https://g.co/amr?c=" + qrcode;
        });
    }
    getGoogleApi() {
        return __awaiter(this, void 0, void 0, function* () {
            var httpgoogle;
            httpgoogle = yield https_1.HttpFunctions.httpGetGoogle();
            var ch = cheerio.load(httpgoogle);
            var allscripts = ch('script').get()[1].children[0].data;
            var reg = /(A16fYe\\x22,\\x5bnull,null,\\x22)(?<GoogleApi>.*?)(\\x22\\x5d\\n\\x5d\\n)/;
            var googleapi = allscripts.match(reg).groups.GoogleApi;
            return googleapi;
        });
    }
    GetRecData(respd) {
        return __awaiter(this, void 0, void 0, function* () {
            var alldresp;
            try {
                alldresp = respd;
                subresp = alldresp[1];
                var b64 = subresp[11];
            }
            catch (_a) {
                try {
                    alldresp = respd[0][1];
                    var b64 = alldresp[1][11];
                }
                catch (_b) {
                    try {
                        alldresp = respd[0][2];
                        var b64 = alldresp[1][11];
                    }
                    catch (_c) {
                        alldresp = respd[0][3];
                        var b64 = alldresp[1][11];
                    }
                }
            }
            var subresp = alldresp[1];
            var respguid = subresp[0];
            var bugled = subresp[7];
            var bugled15 = subresp[8];
            var b64 = subresp[11];
            var subbuffer = Buffer.from(b64, "base64");
            var subrespdata = rawproto_1.getData(subbuffer);
            var newbff = Buffer.from(subrespdata[0][4][1][2]);
            var bufferToMatch = newbff.slice(2, newbff.length - 7);
            var newbase64 = Buffer.from(bufferToMatch).toString('base64');
            var bugle15data = subrespdata[0][4][2][3];
            var bug15 = [
                bugle15data[0][1],
                bugle15data[1][2],
                bugle15data[2][3],
            ];
            return {
                guid: respguid,
                bugle: bugled,
                bugle15: bug15,
                n64: newbase64,
                expdate: 86400000000
            };
        });
    }
    GetPostRefreshToken(crypto_pri_key, crypto_pub_key, bugle15, pr_tachyon_auth_token, googleapi) {
        return __awaiter(this, void 0, void 0, function* () {
            var utimestamp = Math.floor(+new Date() / 1) * 1000;
            var refreqid = yield API.GetReqId();
            var rtoken = yield helpers_1.HelperFunctions.GetRefreshToken(crypto_pri_key, crypto_pub_key, refreqid, utimestamp);
            var refjson = json_1.JsonFunctions.GetRefreshTokenJSON(refreqid, pr_tachyon_auth_token, bugle15, utimestamp, rtoken);
            var httprespack;
            httprespack = yield https_1.HttpFunctions.httpPostAckMessages("/$rpc/google.internal.communications.instantmessaging.v1.Registration/RegisterRefresh", JSON.stringify(refjson), googleapi);
            return httprespack;
        });
    }
    GetdateFromExp(d) {
        var expiredate = d / 60000000;
        var d1 = new Date(), d2 = new Date(d1);
        d2.setMinutes(d1.getMinutes() + expiredate - 60);
        return d2;
    }
    RefreshToken() {
        return __awaiter(this, void 0, void 0, function* () {
            var reftoken = yield this.GetPostRefreshToken(this.sessionData.crypto_pri_key, this.sessionData.crypto_pub_key, this.sessionData.bugle15, this.sessionData.pr_tachyon_auth_token, this.googleapi);
            var respdata = JSON.parse(reftoken);
            var newtacyon = respdata[1][0];
            var newbug15 = respdata[8][0][0];
            this.sessionData.expiredate = this.GetdateFromExp(respdata[1][1]);
            this.sessionData.pr_tachyon_auth_token = newtacyon;
            this.sessionData.bugle15 = newbug15;
            this.emit('sessiondata', JSON.stringify(this.sessionData));
        });
    }
    CheckRefreshToken() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            if ((_a = this.sessionData) === null || _a === void 0 ? void 0 : _a.expiredate) {
                var expData = Date.parse(this.sessionData.expiredate);
                var currdate = Date.now();
                if (expData < currdate) {
                    yield this.RefreshToken();
                }
            }
        });
    }
    Initialise() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.googleapi) {
                yield API.OnLoad();
                this.googleapi = yield this.getGoogleApi();
            }
        });
    }
    QueueFunction(func) {
        return __awaiter(this, void 0, void 0, function* () {
            (() => __awaiter(this, void 0, void 0, function* () {
                try {
                    yield this.queue.add(func);
                }
                catch (err) {
                    this.emit('error', err);
                }
            }))();
        });
    }
    SetupPriorReceive() {
        return __awaiter(this, void 0, void 0, function* () {
            this.emit('debug', "Setting up connection");
            yield this.CheckRefreshToken();
            this.emit('debug', 'Checked refresh token');
            var webenc = yield this.GetWebKey();
            this.emit('debug', 'Got web key');
            this.sessionid = yield API.GetReqId();
            var sendmessageid = yield API.GetReqId();
            this.emit('debug', 'Got request IDs');
            //var sendmess1;
            var sendmess1 = yield this.GetSendMessage(this.sessionid, sendmessageid, 31, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            var sendmess1 = yield this.GetSendMessage(this.sessionid, sendmessageid, 31, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            var sendmess2 = yield this.GetSendMessage(this.sessionid, this.sessionid, 16, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            this.emit('debug', 'Got send message requests');
            this.sessionid = yield API.GetReqId();
            var sendmess3id = yield API.GetReqId();
            var sendmess4id = yield API.GetReqId();
            this.emit('debug', 'Got more request IDs');
            var sendmess3 = yield this.SendWithMessage([16, 25, 32, 1], sendmess3id, this.sessionid, 1, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
            var sendmess4 = yield this.SendWithMessage([16, 1], sendmess4id, this.sessionid, 1, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
            this.emit('debug', 'Sent message requests');
            if (sendmess4) {
                var sResp = JSON.parse(sendmess4);
                if (sResp[0] && sResp[0][1]) {
                }
                else if (sResp[2][0][0] == "type.googleapis.com/google.internal.communications.instantmessaging.v1.TachyonError") {
                    this.emit('error', sResp[1]);
                    return;
                }
            }
            this.emit('debug', 'Connection complete');
            this.connected = true;
            this.retryCount = 0;
            this.StartChecker();
            this.SendReceiveMessages();
        });
    }
    StartChecker() {
        this.StopChecker();
        this.recMessageChecker = setInterval(() => this.CheckLatestReceiveMessages(), 900000);
        this.recMessageCheckerSetup = Date.now();
    }
    StopChecker() {
        if (this.recMessageChecker)
            clearInterval(this.recMessageChecker);
    }
    CheckLatestReceiveMessages() {
        this.emit('debug', "Checking last update from Receive messages - " + this.lastRecReceived);
        if (this.lastRecReceived < this.recMessageCheckerSetup) {
            this.emit('error', 'Not receiving new recieve messages');
        }
        this.recMessageCheckerSetup = Date.now();
    }
    SendReceiveMessages() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield this.GetNewRecMessages();
                this.emit('error', "Connection ended");
            }
            catch (err) {
                this.emit('error', err);
            }
        });
    }
    GetWebKey() {
        return __awaiter(this, void 0, void 0, function* () {
            var webgetwebenc = yield this.GetWebEnc(this.googleapi, this.sessionData.pr_tachyon_auth_token);
            var bweb = Buffer.from(webgetwebenc);
            var webenccryptokey = yield this.GetEncryptionData(bweb);
            return webenccryptokey;
        });
    }
    GetNewRecMessages() {
        return __awaiter(this, void 0, void 0, function* () {
            var resp = yield this.GetRecMessages(this.sessionData.pr_tachyon_auth_token, this.googleapi, (data) => __awaiter(this, void 0, void 0, function* () {
                this.lastRecReceived = Date.now();
                this.emit('receivemessage', JSON.stringify(data));
                return false;
            }));
        });
    }
    ProcessNewReceiveMessage(data) {
        return __awaiter(this, void 0, void 0, function* () {
            var deckey = Buffer.from(this.sessionData.crypto_msg_enc_key, 'base64');
            try {
                var chunksToEmit = [];
                var chunks = yield this.ProcessChunks(data, deckey);
                var chunkdata = chunks.currentChunks;
                for (var i = 0; i < chunkdata.length; i++) {
                    var chunk = chunkdata[i];
                    if (chunk.guid && this.processedChunks2.indexOf(chunk.guid) < 0) {
                        try {
                            this.processedChunks2.push(chunk.guid);
                            if (chunk.data[0] === 50 && chunk.data[1] === 2 && chunk.data[2] === 16 && chunk.data[3] === 1) {
                                this.emit('error', 'Connection overridden by another instance');
                            }
                            var chunk1 = yield API.ChunkProcess(chunk.data);
                            if (chunk1.hh && chunk1.hh[1] && chunk1.hh[1][0] && chunk1.hh[1][0][0] && chunk1.hh[1][0][3] && chunk1.hh[1][0][3][0]) {
                                this.messageListFound = true;
                                var allmessages = chunk1.hh[1];
                                var allmessagesBetter = allmessages.map(x => (helpers_1.HelperFunctions.ProcessConvData(x)));
                                this.emit('convlist', JSON.stringify(allmessagesBetter));
                                continue;
                            }
                            if (this.messageListFound == false)
                                continue;
                            var chunk0 = yield API.ChunkProcessNew(Buffer.from(chunk.data).toString('base64'), false, true);
                            if (chunk0.hh && chunk0.hh[1] && chunk0.hh[1][0] && chunk0.hh[1][0][0]) {
                                var allconvs = chunk0.hh[1];
                                var allconvsBetter = allconvs.map(x => (helpers_1.HelperFunctions.ProcessMsgData(x, this.tempIdsSending)));
                                this.emit('messagelist', JSON.stringify(allconvsBetter));
                                continue;
                            }
                            var chunk3 = yield API.ChunkProcessNew(Buffer.from(chunk.data).toString('base64'), false, false);
                            if (chunk3.hh && chunk3.hh[1] && chunk3.hh[1][0] && chunk3.hh[1][0][0]) {
                                try {
                                    var allmessages = chunk3.hh[1];
                                    var allmessagesBetter = allmessages.map(x => helpers_1.HelperFunctions.ProcessConvData(x));
                                    this.emit('convlist', JSON.stringify(allmessagesBetter));
                                    continue;
                                }
                                catch (_a) { }
                            }
                            var chunk2 = yield API.ChunkProcessNew(Buffer.from(chunk.data).toString('base64'), true, false);
                            if (chunk2.hh && chunk2.hh[1] && chunk2.hh[1][0] && chunk2.hh[1][0][0]) {
                                var allconvs = chunk2.hh[1];
                                var allconvsBetter = allconvs.map(x => (helpers_1.HelperFunctions.ProcessMsgData(x, this.tempIdsSending)));
                                var groups = helpers_1.HelperFunctions.groupBy2(allconvsBetter, 'StatusId');
                                for (var g in groups) {
                                    if (g == "100" || g == "1") {
                                        this.emit('messagelist', JSON.stringify(groups[g]));
                                    }
                                    else {
                                        this.emit('messageupdate', JSON.stringify(groups[g]));
                                    }
                                }
                                continue;
                            }
                        }
                        catch (err) {
                            var error = err;
                        }
                    }
                }
                if (chunks.currentGuids.length > 0) {
                    var respack = yield this.GetAckMessages(this.sessionData.pr_tachyon_auth_token, chunks.currentGuids, this.googleapi);
                }
            }
            catch (_b) {
            }
        });
    }
    TriggerGetMessages(convId) {
        return __awaiter(this, void 0, void 0, function* () {
            var reqarr = yield API.GetRequestConv2(convId);
            var sendmess3id = yield API.GetReqId();
            var sendmess3 = yield this.SendWithMessage(reqarr, sendmess3id, this.sessionid, 2, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
        });
    }
    ProcessChunks(respd, deckey) {
        return __awaiter(this, void 0, void 0, function* () {
            const currentChunks = [];
            const currentGuids = [];
            var allconv = respd[0];
            for (var i = 0; i < allconv.length; i++) {
                var currentItem = allconv[i];
                const currentItemGuid = currentItem[1] ? currentItem[1][0] : null;
                if (currentItemGuid && this.processedChunks.indexOf(currentItemGuid) < 0) {
                    currentGuids.push(currentItemGuid);
                    try {
                        var lastdata = currentItem[1][11];
                        var proto = Buffer.from(lastdata, 'base64');
                        proto = rawproto_1.getData(proto);
                        var conv = proto[3][8] ? proto[3][8] : proto[4][8];
                        var decdata;
                        try {
                            decdata = yield helpers_1.HelperFunctions.DeCryptMessage2(Buffer.from(conv, 'base64'), deckey);
                        }
                        catch (_a) {
                            decdata = yield helpers_1.HelperFunctions.DeCryptMessage2(Buffer.from(conv), deckey);
                        }
                        this.processedChunks.push(currentItemGuid);
                        if (decdata) {
                            currentChunks.push({
                                item: currentItem,
                                guid: currentItemGuid,
                                data: decdata
                            });
                        }
                    }
                    catch (_b) { }
                }
            }
            return ({ currentChunks, currentGuids });
        });
    }
    SendWithMessage(message, sendmessageid, sessionid, midcode, crypto_msg_enc_key, crypto_msg_hmac, bugle, pr_tachyon_auth_token, googleapi) {
        return __awaiter(this, void 0, void 0, function* () {
            var mydata = yield helpers_1.HelperFunctions.EncryptMessage(message, crypto_msg_enc_key, crypto_msg_hmac);
            var sendmess2 = yield this.GetSendMessage(sessionid, sendmessageid, midcode, bugle, pr_tachyon_auth_token, googleapi, mydata);
            return sendmess2;
        });
    }
    GetEncryptionData(webenc) {
        return __awaiter(this, void 0, void 0, function* () {
            var bweb = Buffer.from(webenc);
            var uint = new Uint8Array(bweb);
            var decpart1 = uint.slice(0, 15);
            var decpart2 = uint.slice(15, 47);
            var subk = decpart2.slice(0, 16);
            var k1k = yield API.GetKeyFromWebE(subk);
            var b = {
                kty: "oct",
                k: k1k,
                alg: "A128GCM",
                ext: !0
            };
            return yield subtle.importKey("jwk", b, {
                name: "AES-GCM"
            }, !1, ["encrypt", "decrypt"]);
        });
    }
    RegisterAndGetQR(pubkeyexp, googleapi, crypto_msg_enc_key, crypto_msg_hmac) {
        return __awaiter(this, void 0, void 0, function* () {
            var resp = yield API.Setup(pubkeyexp);
            var httpresp;
            httpresp = yield https_1.HttpFunctions.httpPostPhoneRelay(resp.protodata, googleapi);
            var data = rawproto_1.getData(httpresp.slice(15, -8));
            var qrreqdata = data[2][3];
            var qrlink = yield this.getQRCodeLink(qrreqdata, crypto_msg_enc_key, crypto_msg_hmac);
            return {
                RelayData: data,
                QRLink: qrlink
            };
        });
    }
    GetAckMessages(n64, guids, googleapi) {
        return __awaiter(this, void 0, void 0, function* () {
            var ackreqid = yield API.GetReqId();
            var ackmessage = json_1.JsonFunctions.getAckMessagesStringJSON(ackreqid, guids, n64, 8);
            var httprespack = yield https_1.HttpFunctions.httpPostAckMessages("/$rpc/google.internal.communications.instantmessaging.v1.Messaging/AckMessages", JSON.stringify(ackmessage), googleapi);
            return httprespack;
        });
    }
    GetRecMessages(pr_tachyon_auth_token, googleapi, callback) {
        return __awaiter(this, void 0, void 0, function* () {
            var reqid = yield API.GetReqId();
            var respstring = json_1.JsonFunctions.getRecMessagesStringJSON(reqid, pr_tachyon_auth_token, 8);
            var respd = yield https_1.HttpFunctions.httpPostRecMessages(JSON.stringify(respstring), googleapi, callback);
            return respd;
        });
    }
    GetWebEnc(googleapi, n64) {
        return __awaiter(this, void 0, void 0, function* () {
            var uintbuf = Buffer.from(n64, 'base64');
            var uint8conv = new Uint8Array(uintbuf);
            var ackreqid = yield API.EncKey(uint8conv);
            var httprespwebenc;
            httprespwebenc = yield https_1.HttpFunctions.httpPostWebEnc(ackreqid, googleapi);
            return httprespwebenc;
        });
    }
    GetSendMessage(sessionid, sendmessageid, midcode, bugleresp, uint8qr1, googleapi, message) {
        return __awaiter(this, void 0, void 0, function* () {
            var sendproto = yield API.GetSendMessage(sendmessageid, sessionid, midcode, message);
            var sendprotoBuff = Buffer.from(sendproto).toString("base64");
            var sendjsonstring = json_1.JsonFunctions.getSendMessagesStringJSON(bugleresp, sendmessageid, uint8qr1, sendprotoBuff);
            var httprespack;
            httprespack = yield https_1.HttpFunctions.httpPostAckMessages("/$rpc/google.internal.communications.instantmessaging.v1.Messaging/SendMessage", JSON.stringify(sendjsonstring), googleapi);
            return httprespack;
        });
    }
}
exports.MessagesClient = MessagesClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2FnZXMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvbWVzc2FnZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBQUEsdUNBQW1DO0FBQ25DLDZCQUE2QjtBQUM3QixtQ0FBbUM7QUFDbkMsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLE9BQU8sQ0FBQyxRQUFRLENBQUMsQ0FBQyxTQUFTLENBQUM7QUFDL0MsbUNBQXdDO0FBQ3hDLGlDQUF1QztBQUN2Qyx1Q0FBNEM7QUFDNUMsMkRBQWtEO0FBQ2xELHFDQUEwQztBQWUxQyxNQUFhLGNBQWUsU0FBUSxpQ0FBa0M7SUFBdEU7O1FBRVksVUFBSyxHQUFHLElBQUksaUJBQU0sQ0FBQyxFQUFDLFdBQVcsRUFBRSxDQUFDLEVBQUMsQ0FBQyxDQUFDO1FBSXJDLG1CQUFjLEdBQVMsRUFBRSxDQUFDO1FBQzFCLG9CQUFlLEdBQVUsRUFBRSxDQUFDO1FBQzVCLHFCQUFnQixHQUFVLEVBQUUsQ0FBQztRQUM3QixxQkFBZ0IsR0FBRyxLQUFLLENBQUM7UUFDekIsZUFBVSxHQUFHLENBQUMsQ0FBQztRQUloQixjQUFTLEdBQUcsS0FBSyxDQUFDO1FBK0pqQixRQUFHLEdBQUcsVUFBUyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUM7WUFDMUIsTUFBTSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLEVBQ3ZCLENBQUMsR0FBRyxJQUFJLFFBQVEsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDL0IsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ1YsT0FBTyxDQUFDLEdBQUcsQ0FBQztnQkFDUixDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDO29CQUN0QixDQUFDLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLEdBQUcsR0FBRyxDQUFDO29CQUN2QixDQUFDLEVBQUUsQ0FBQztZQUNSLENBQUMs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