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
const messages_1 = require("./messages");
const QRCode = require("qrcode");
const fs_1 = require("fs");
const manager_1 = require("./manager");
const messages = new messages_1.MessagesClient();
(() => __awaiter(void 0, void 0, void 0, function* () {
    //create data folder to store session data and message ids for each conversation.
    if (!fs_1.existsSync("data")) {
        fs_1.mkdirSync("data");
    }
    // run this first to setup new client and get QR code. once scanned, all events after should be emitted including conversation list and messages etc.
    yield New();
    //run this after initial setup has already been complete to use session data from New function
    //await Existing();
}))();
function Read(fileLoc) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            var sessionDataStr;
            sessionDataStr = fs_1.readFileSync(fileLoc);
            var sessionData = JSON.parse(sessionDataStr);
            return sessionData;
        }
        catch (_a) { }
        return null;
    });
}
;
function Save(sessionData, fileLoc) {
    return __awaiter(this, void 0, void 0, function* () {
        fs_1.writeFileSync(fileLoc, sessionData);
    });
}
;
function LogMessge(str) {
    return __awaiter(this, void 0, void 0, function* () {
        console.log(new Date().toLocaleString() + " - " + str);
    });
}
process.on('SIGINT', function () {
    return __awaiter(this, void 0, void 0, function* () {
        LogMessge("Caught interrupt signal");
        yield messages.Close();
        process.exit();
    });
});
function New() {
    return __awaiter(this, void 0, void 0, function* () {
        var mc = new messages_1.MessagesClient();
        mc.on('error', (e) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("ERROR - " + e);
        }));
        mc.on('qrcode', (u) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("QR CODE Found - " + u);
            yield SaveQRCode(u, "myqrcode.png");
        }));
        mc.on('sessiondata', (sd) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("Updated session data");
            Save(sd, "data/sessionData.txt");
            yield Existing();
        }));
        yield mc.Connect();
    });
}
var msgData;
function Existing() {
    return __awaiter(this, void 0, void 0, function* () {
        messages.on('closed', (m) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("Closed - " + m);
        }));
        messages.on('error', (e) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("ERROR - " + e);
        }));
        messages.on('sessiondata', (sd) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("Updated session data");
            Save(sd, "data/sessionData.txt");
        }));
        messages.on('invalidtoken', (sd) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("Invalid Token");
        }));
        messages.on('convlist', (m) => __awaiter(this, void 0, void 0, function* () {
            var messagesFound = JSON.parse(m);
            var retmsgData = manager_1.MessagesManager.SetupMsgData(msgData, messagesFound);
            msgData = retmsgData.MessageData;
            for (var newm in retmsgData.ConversationsNeeded) {
                var conv = retmsgData.ConversationsNeeded[newm];
                yield messages.GetMessages(conv);
            }
            Save(JSON.stringify(msgData), "data/msgData.txt");
        }));
        messages.on('debug', (m) => __awaiter(this, void 0, void 0, function* () {
            LogMessge("New debug message - " + m);
        }));
        messages.on('messageupdate', (m) => __awaiter(this, void 0, void 0, function* () {
            var updateFound = JSON.parse(m);
            LogMessge("Messages Update for id - " + updateFound[0].ConvId + " - " + updateFound[0].StatusText);
        }));
        messages.on('messagelist', (m) => __awaiter(this, void 0, void 0, function* () {
            var p;
            p = {};
            p.data = {};
            p.data.MessageData = msgData;
            var messagesFound = JSON.parse(m);
            var newMessages = yield manager_1.MessagesManager.SetupConvData(msgData, messagesFound, messages);
            for (var newm in newMessages) {
                var mess = newMessages[newm];
                LogMessge("New Message Received");
                msgData.ProcessedMessages.push(mess.MsgId);
            }
            Save(JSON.stringify(msgData), "data/msgData.txt");
        }));
        var sessionData = yield Read("data/sessionData.txt");
        try {
            msgData = yield Read("data/msgData.txt");
        }
        catch (_a) { }
        yield messages.Setup(sessionData);
    });
}
var allMessages = [];
function SaveQRCode(qrlink, fileloc) {
    return __awaiter(this, void 0, void 0, function* () {
        var imgurl = yield QRCode.toDataURL(qrlink);
        var base64Data = imgurl.replace(/^data:image\/png;base64,/, "");
        fs_1.writeFileSync(fileloc, base64Data, 'base64');
    });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3NyYy90ZXN0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBQUEseUNBQTRDO0FBQzVDLGlDQUFpQztBQUNqQywyQkFBd0U7QUFDeEUsdUNBQTRDO0FBSTVDLE1BQU0sUUFBUSxHQUFJLElBQUkseUJBQWMsRUFBRSxDQUFDO0FBRXZDLENBQUMsR0FBUyxFQUFFO0lBRVIsaUZBQWlGO0lBQ2pGLElBQUksQ0FBQyxlQUFVLENBQUMsTUFBTSxDQUFDLEVBQUM7UUFDcEIsY0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0tBQ3JCO0lBRUQscUpBQXFKO0lBQ3JKLE1BQU0sR0FBRyxFQUFFLENBQUM7SUFFWiw4RkFBOEY7SUFDOUYsbUJBQW1CO0FBQ3ZCLENBQUMsQ0FBQSxDQUFDLEVBQUUsQ0FBQztBQUdMLFNBQWUsSUFBSSxDQUFDLE9BQWU7O1FBQy9CLElBQUk7WUFDQSxJQUFJLGNBQWMsQ0FBQztZQUFDLGNBQWMsR0FBRyxpQkFBWSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1lBQzNELElBQUksV0FBVyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsY0FBYyxDQUFDLENBQUM7WUFDN0MsT0FBTyxXQUFXLENBQUM7U0FDdEI7UUFBQyxXQUFNLEdBQUc7UUFDWCxPQUFPLElBQUksQ0FBQztJQUNoQixDQUFDO0NBQUE7QUFBQSxDQUFDO0FBRUYsU0FBZSxJQUFJLENBQUMsV0FBZ0IsRUFBRSxPQUFlOztRQUNqRCxrQkFBYSxDQUFDLE9BQU8sRUFBRSxXQUFXLENBQUMsQ0FBQztJQUN4QyxDQUFDO0NBQUE7QUFBQSxDQUFDO0FBRUYsU0FBZSxTQUFTLENBQUMsR0FBRzs7UUFDeEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLElBQUksRUFBRSxDQUFDLGNBQWMsRUFBRSxHQUFHLEtBQUssR0FBRyxHQUFHLENBQUMsQ0FBQztJQUMzRCxDQUFDO0NBQUE7QUFFRCxPQUFPLENBQUMsRUFB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