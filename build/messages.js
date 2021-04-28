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
            var webenc = yield this.GetWebKey();
            this.sessionid = yield API.GetReqId();
            var sendmessageid = yield API.GetReqId();
            //var sendmess1;
            var sendmess1 = yield this.GetSendMessage(this.sessionid, sendmessageid, 31, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            var sendmess1 = yield this.GetSendMessage(this.sessionid, sendmessageid, 31, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            var sendmess2 = yield this.GetSendMessage(this.sessionid, this.sessionid, 16, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi, new Uint8Array(0));
            this.sessionid = yield API.GetReqId();
            var sendmess3id = yield API.GetReqId();
            var sendmess4id = yield API.GetReqId();
            var sendmess3 = yield this.SendWithMessage([16, 25, 32, 1], sendmess3id, this.sessionid, 1, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
            var sendmess4 = yield this.SendWithMessage([16, 1], sendmess4id, this.sessionid, 1, this.sessionData.crypto_msg_enc_key, this.sessionData.crypto_msg_hmac, this.sessionData.bugle, this.sessionData.pr_tachyon_auth_token, this.googleapi);
            if (sendmess4) {
                var sResp = JSON.parse(sendmess4);
                if (sResp[0] && sResp[0][1]) {
                }
                else if (sResp[2][0][0] == "type.googleapis.com/google.internal.communications.instantmessaging.v1.TachyonError") {
                    this.emit('error', sResp[1]);
                    return;
                }
            }
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibWVzc2FnZXMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi9zcmMvbWVzc2FnZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBQUEsdUNBQW1DO0FBQ25DLDZCQUE2QjtBQUM3QixtQ0FBbUM7QUFDbkMsTUFBTSxFQUFFLE1BQU0sRUFBRSxHQUFHLE9BQU8sQ0FBQyxRQUFRLENBQUMsQ0FBQyxTQUFTLENBQUM7QUFDL0MsbUNBQXdDO0FBQ3hDLGlDQUF1QztBQUN2Qyx1Q0FBNEM7QUFDNUMsMkRBQWtEO0FBQ2xELHFDQUEwQztBQWUxQyxNQUFhLGNBQWUsU0FBUSxpQ0FBa0M7SUFBdEU7O1FBRVksVUFBSyxHQUFHLElBQUksaUJBQU0sQ0FBQyxFQUFDLFdBQVcsRUFBRSxDQUFDLEVBQUMsQ0FBQyxDQUFDO1FBSXJDLG1CQUFjLEdBQVMsRUFBRSxDQUFDO1FBQzFCLG9CQUFlLEdBQVUsRUFBRSxDQUFDO1FBQzVCLHFCQUFnQixHQUFVLEVBQUUsQ0FBQztRQUM3QixxQkFBZ0IsR0FBRyxLQUFLLENBQUM7UUFDekIsZUFBVSxHQUFHLENBQUMsQ0FBQztRQWlLZixRQUFHLEdBQUcsVUFBUyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUM7WUFDMUIsTUFBTSxDQUFDLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDLEVBQ3ZCLENBQUMsR0FBRyxJQUFJLFFBQVEsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUM7WUFDL0IsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO1lBQ1YsT0FBTyxDQUFDLEdBQUcsQ0FBQztnQkFDUixDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxDQUFDLEdBQUcsR0FBRyxDQUFDO29CQUN0QixDQUFDLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLEdBQUcsR0FBRyxDQUFDO29CQUN2QixDQUFDLEVBQUUsQ0FBQztZQUNSLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLFFB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