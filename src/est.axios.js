

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
        const { id, secret, scope } = this;
        if ( this.token && this.time > Date.now() ){ // 토큰이 유효함
            return Promise.resolve(this.token);
        }

        return axios.post(`https://id.twitch.tv/oauth2/token?client_id=${id}&client_secret=${secret}&grant_type=client_credentials${scope ? '&' : ''}${scope.join('%20')}`).then(( { data : token})=>{
            const { access_token, expires_in } = token;

            _this.token = {
                'Client-ID': id,
                Authorization: `Bearer ${access_token}`,
                'Content-Type': 'application/json',
            };
            _this.time = Date.new() + expires_in;   

            return _this.token;
        })
    }


}


// 라이브러리 매인 클래스
class EST extends EventEmitter{
    constructor (id, secret, options = {}){
        if ( EST._instance ) return EST._instance;
        EST._instance = this;

        // { scope, apiTarget }
        options.apiTarget = options.apiTarget || "helix"; // api version

        this.options = options;


        this.eventQueue = [];

        this._id = id;
        this._secret = secret;

        this._token = new Token(id, secret, options.scope);

    }

    _api(target, url, body){
        const _this = this;
        const { apiTarget } = this.options;
        return this._token.getToken().then(head => 
            axios[target](`https://api.twitch.tv/${apiTarget}/${url}`, body, head).catch(e=>{
                const { response } = e;
                if (response.status == 429) {
                    const {
                        headers: { 'ratelimit-limit': limitSize, 'ratelimit-remaining': limit, 'ratelimit-reset': reset },
                    } = response;
                    console.log(`레이트 리미팅 - ${limitSize}/${limit} [대기시간 : ${reset}]`);

                    return rateLimitFunction(reset).then(_=>_this._api(target, url, body));
                }
                return Promise.reject(e);
            })
        );
    }

    getApi(url){
        return _api('get', url);
    }

    postApi(url, body){
        return _api('post', url, body);
    }

    deleteApi(url, body){
        return _api('delete', url, body);
    }

    // 
    router(req, res){
        const _this = this;
        let { body } = req;
        if (Buffer.isBuffer(req.body)) {
            body = JSON.parse(Buffer.toString(body));
        } else if (typeof body === "string") {
            body = JSON.parse(decodeURIComponent(body));
        }                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      zzzzzzzzzzzzzzzzzzzzzzz        
        
        if ( req.headers && req.headers.hasOwnProperty("twitch-eventsub-message-signature")){ // 인증
            const { headers } = req;

            const id = headers["twitch-eventsub-message-id"];
            const timestamp = headers["twitch-eventsub-message-timestamp"];
            const signature = headers["twitch-eventsub-message-signature"].split("=");

            const buf = Buffer.from(JSON.stringify(body));
            const calculated_signature = crypto
                .createHmac(signature[0], _this._secret)
                .update(id + timestamp + buf)
                .digest("hex");

            if ( calculated_signature == signature[1]){ // 복호화 성공
                if ( body.hasOwnProperty("challenge") &&
                    headers["twitch-eventsub-message-type"] === "webhook_callback_verification" 
                ){ // 이벤트 등록 실패
                    res.status(200)
                        .type("text/plain")
                        .send(encodeURIComponent(body.challenge));
                    return;
                }
                res.status(200).send("OK");

                const messageId = headers["twitch-eventsub-message-id"];

                if (_this.eventQueue.recentMessageIds[messageId])return; // 중복수신

                const messageAge = Date.now() - new Date(timestamp);
                if ( messageAge > 600000) { // 오래된 메세지
                    return;
                }

                switch (headers["twitch-eventsub-message-type"]) {
                    case "notification":
                        _this.emit("log", `Received notification for type ${body.subscription.type}`);
                        // logger.log(`Received notification for type ${body.subscription.type}`);
                        _this.eventQueue.recentMessageIds[messageId] = true;
                        setTimeout(() => delete _this.eventQueue.recentMessageIds[messageId], 601000);
                        // EventManager.fire(body.subscription, body.event);
                        break;
                    case "revocation": // 이벤트 등록 에러
                        _this.emit("log", `Received revocation notification for subscription id ${body.subscription.id}`);
                        _this.eventQueue.recentMessageIds[messageId] = true;
                        setTimeout(() => delete _this.eventQueue.recentMessageIds[messageId] , 601000);
                        _this.emit('')
                        // EventManager.fire({ ...body.subscription, type: "revocation" }, body.subscription);
                        break;
                    default:
                        _this.emit("log", `Received request with unhandled message type ${headers["twitch-eventsub-message-type"]}`);
                        break;
                }

            }
            return;
        }else res.status(401).send("Unauthorized request to EventSub webhook");
    }

    
}


module.exports = EST;