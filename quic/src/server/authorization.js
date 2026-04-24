'use strict';

const crypto = require('crypto');

class AuthService {
    constructor(secret) {
        this.secret = secret || 'fitfak-super-secure-key-2026';
        this.users = {
            'aybars': { id: 1, pass: '123', name: 'Aybars' },
            'test1':  { id: 2, pass: '123', name: 'Test 1' },
            'test2':  { id: 3, pass: '123', name: 'Test 2' }
        };
    }

    signJWT(payload) {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }), 'utf8').toString('base64url');
        const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
        const signature = crypto.createHmac('sha256', this.secret).update(`${header}.${data}`).digest('base64url');
        return `${header}.${data}.${signature}`;
    }

    verifyJWT(token) {
        try {
            if (!token) return null;
            const parts = token.trim().split('.');
            if (parts.length !== 3) return null;

            const [header, data, signature] = parts;
            const expectedSig = crypto.createHmac('sha256', this.secret).update(`${header}.${data}`).digest('base64url');
            
            if (signature !== expectedSig) return null;

            const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
            if (payload.exp && payload.exp < Date.now()) return null;

            return payload;
        } catch (e) {
            return null;
        }
    }

    authenticate(username, password) {
        const user = this.users[username];
        if (user && user.pass === password) {
            return { id: user.id, name: user.name };
        }
        return null;
    }

    parseCookies(cookieStr) {
        if (!cookieStr || typeof cookieStr !== 'string') return {};
        return cookieStr.split(';').reduce((res, item) => {
            const parts = item.trim().split('=');
            if (parts.length >= 2) {
                const key = parts.shift();
                const val = parts.join('=');
                res[key] = decodeURIComponent(val);
            }
            return res;
        }, {});
    }
}

module.exports = { AuthService };