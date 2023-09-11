import {
    Context, Handler, superagent, SystemModel, TokenModel, UserFacingError, param, Types, Logger
} from 'hydrooj';

const logger = new Logger('login-with-fudanuis');

declare module 'hydrooj' {
    interface SystemKeys {
        'login-with-fudanuis.id': string,
        'login-with-fudanuis.secret': string,
    }
}

async function get(this: Handler) {
    const [appid, url, [state]] = await Promise.all([
        SystemModel.get('login-with-fudanuis.id'),
        SystemModel.get('server.url'),
        TokenModel.add(TokenModel.TYPE_OAUTH, 600, { redirect: this.request.referer }),
    ]);
    // eslint-disable-next-line max-len
    this.response.redirect = `https://tac.fudan.edu.cn/oauth2/authorize.act?client_id=${appid}&response_type=code&redirect_uri=${url}login_oauth_authorize&scope=basic&state=${state}`;
}

function unescapedString(escapedString: string) {
    escapedString += new Array(5 - (escapedString.length % 4)).join('=');
    return escapedString.replace(/-/g, '+').replace(/_/g, '/');
}

function decodeJWT(idToken: string) {
    const token = idToken.split('.');
    if (token.length !== 3) throw new Error('Invalid idToken');
    try {
        const headerSegment = JSON.parse(Buffer.from(token[0], 'base64').toString('utf8'));
        const payloadSegment = JSON.parse(Buffer.from(token[1], 'base64').toString('utf8'));
        const signature = unescapedString(token[2]);
        return {
            dataToSign: [token[0], token[1]].join('.'),
            header: headerSegment,
            payload: payloadSegment,
            signature,
        };
    } catch (e) {
        throw new Error('Invalid payload');
    }
}

async function callback(this: Handler, {
    access_token, state, expires_in, scope, error,
}) {
    logger.info(access_token)
    logger.info(state)
    logger.info(scope)
    if (error) throw new UserFacingError(error);
    const [[appid, secret, url], s] = await Promise.all([
        SystemModel.getMany([
            'login-with-fudanuis.id', 'login-with-fudanuis.secret', 'server.url',
        ]),
        TokenModel.get(state, TokenModel.TYPE_OAUTH),
    ]);
    const res = await superagent.post(`https://tac.fudan.edu.cn/resource/userinfo.act?access_token=${access_token}`);
    logger.info(res.body)
    // const payload = decodeJWT(res.body.id_token).payload;
    await TokenModel.del(state, TokenModel.TYPE_OAUTH);
    this.response.redirect = s.redirect;
    let n = Number(res.body.user_id)
    return {
        // TODO use openid
        _id: res.body.user_id,
        email: res.body.user_id + (n > 21000000000 ? "@m.fudan.edu.cn" : "@fudan.edu.cn")
    };
}

class FudanLoginHandler extends Handler
{
    @param('access_token', Types.String)
    @param('scope', Types.String)
    @param('state', Types.String)
    @param('expires_in', Types.Int)
    async get(domainId: string, access_token: string, scope: string, state: string, expires_in: bigint) {
        const [url] = await Promise.all([
            SystemModel.get('server.url'),
        ]);
        this.response.redirect = `${url}oauth/fudanuis/callback?access_token=${access_token}&scope=${scope}&state=${state}&expires_in=${expires_in}`
    }
}

class FudanLoginAuthorizeHandler extends Handler
{
    @param('client_id', Types.String)
    @param('state', Types.String)
    async get(domainId: string, client_id: string, state: string) {
        const [url] = await Promise.all([
            SystemModel.get('server.url'),
        ]);
        this.response.redirect = `https://tac.fudan.edu.cn/oauth2/authorize.act?client_id=${client_id}&response_type=token&redirect_uri=${url}login_oauth&scope=basic&state=${state}`
    }
}

export function apply(ctx: Context) {
    ctx.provideModule('oauth', 'fudanuis', {
        text: 'Login with Fudan UIS',
        callback,
        get,
    });
    ctx.Route('fudan_uis_logintemp', '/login_oauth_authorize', FudanLoginAuthorizeHandler)
    ctx.Route('fudan_uis_login', '/login_oauth', FudanLoginHandler);
    ctx.i18n.load('zh', {
        'Login with Fudan UIS': '使用复旦 UIS 登录',
    });
}
