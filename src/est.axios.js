

const express = require("express");
const crypto = require("crypto");
const axios = require('axios');
const EventEmitter = require('node:events');
const { workerData } = require("worker_threads");

const rateLimitFunction = (time) => new Promise((r, q) => setTimeout(r, time));
class Token {
    constructor(id, secret, scope){
        
        this.id = id;
        this.secret = secret;
        this.scope = scope;

        this.time = 0;
        this.token = null;
    }

    getToken(){
        const _this = this;
        if ( _this.token && _this.time > Date.now() ){ // 토큰이 유효함
            return Promise.resolve(_this.token);
        }
        const { id, secret, scope } = this;

        return axios.post(`https://id.twitch.tv/oauth2/token?client_id=${id}&client_secret=${secret}&grant_type=client_credentials${scope ? '&' : ''}${scope.join('%20')}`).then(( { data : token})=>{
            const { access_token, expires_in } = token;
            _this.time = Date.now() + expires_in - (10 * 1000); // 10 초전
            _this.token = {
                'Client-ID': id,
                Authorization: `Bearer ${access_token}`,
                'Content-Type': 'application/json',
            };

            return _this.token;
        })
    }
}

// 라이브러리 매인 클래스
class EST extends EventEmitter{
    constructor (id, secret, options = {}){
        super();
        if ( EST._instance ) return EST._instance;

        if (!(this instanceof EST)) {
            return new EST(config);
        }
        EST._instance = this;

        // { scope, apiTarget }
        options.apiTarget = options.apiTarget || "helix"; // api version
        options.secret = options.secret || secret; // api version

        this.options = options;


        this.eventQueue = [];

        this._id = id;
        this._secret = secret;

        this._token = new Token(id, secret, options.scope);

    }

    getToken(){
        return this._token.getToken();
    }

    _api(target, url, body){
        const _this = this;
        const { apiTarget } = this.options;
        return this._token.getToken().then(headers => {
            
            axios[target](`https://api.twitch.tv/${apiTarget}/${url}`, body, { headers }).catch(e=>{
                const { response } = e;
                if (response.status == 429) {
                    const {
                        headers: { 'ratelimit-limit': limitSize, 'ratelimit-remaining': limit, 'ratelimit-reset': reset },
                    } = response;
                    console.log(`레이트 리미팅 - ${limitSize}/${limit} [대기시간 : ${reset}]`);

                    return rateLimitFunction(reset).then(_=>_this._api(target, url, body));
                }
                return e;
            })
        }
        );
    }

    getApi(url){
        return this._api('get', url);
    }

    postApi(url, body){
        return this._api('post', url, body);
    }

    deleteApi(url, body){
        return this._api('delete', url, body);
    }

    // EventSub 용 라우터
    router(req, res){
        const _this = this;
        let { body } = req;
        if (Buffer.isBuffer(req.body)) {
            body = JSON.parse(Buffer.toString(body));
        } else if (typeof body === "string") {
            body = JSON.parse(decodeURIComponent(body));
        }
        // console.log(req.headers)

        if ( req.headers && req.headers.hasOwnProperty("twitch-eventsub-message-signature")){ // 인증
            const { headers } = req;

            const id = headers["twitch-eventsub-message-id"];
            const timestamp = headers["twitch-eventsub-message-timestamp"];
            const [hash, secret_value] = headers["twitch-eventsub-message-signature"].split("=");

            const buf = Buffer.from(JSON.stringify(body));
            const calculated_signature = crypto
                .createHmac(hash, _this.options.secret)
                .update(id + timestamp + buf)
                .digest("hex");

            if ( calculated_signature == secret_value){ // 복호화 성공
                if ( body.hasOwnProperty("challenge") &&
                    headers["twitch-eventsub-message-type"] === "webhook_callback_verification" 
                ){ // 이벤트 등록
                    res.status(200)
                        .type("text/plain")
                        .send(encodeURIComponent(body.challenge));
                    _this.emit('register',body.event,body.subscription);
                    return;
                }
                res.status(200).send("OK");

                const messageId = headers["twitch-eventsub-message-id"];
                if (_this.eventQueue[messageId])return; // 중복수신

                const messageAge = Date.now() - new Date(timestamp);
                if ( messageAge > 600000) return; // 오래된 메세지
                    

                switch (headers["twitch-eventsub-message-type"]) {
                    case "notification":
                        _this.emit("log", `Received notification for type ${body.subscription.type}`);
                        _this.eventQueue[messageId] = true;
                        _this.emit(body.subscription.type,body.event,body.subscription);
                        setTimeout(() => delete _this.eventQueue[messageId], 601000);
                        break;
                    case "revocation": // 이벤트 등록 에러
                        _this.emit("log", `Received revocation notification for subscription id ${body.subscription.id}`);
                        _this.eventQueue[messageId] = true;
                        _this.emit('revocation', body.event, body.subscription);
                        setTimeout(() => delete _this.eventQueue[messageId] , 601000);
                        break;
                    default:
                        _this.emit("error", `Received request with unhandled message type ${headers["twitch-eventsub-message-type"]}`);
                        break;
                }

            }
            return;
        } else {
            res.status(401).send("Unauthorized request to EventSub webhook");
        }
    }

    
}


module.exports = EST;