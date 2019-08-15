import {AbstractAuth, IAuthError, IAuthIdentity, IIdentityResult, failure, success, GenericResult} from "@skazska/abstract-service-model";
import {verify, sign} from "jsonwebtoken";

//TODO this is to implement later

export const SECRET = 'secret';

export class JWTAuthIdentity implements IAuthIdentity {
    constructor(private token :string, protected _secret :any) {}

    protected secret() :string {
        return <string>this._secret;
    }

    access(realm :string, op: string) :Promise<GenericResult<boolean, IAuthError>> {
        try {
            let re = new RegExp('^(?:.*[|:;,\\/])*' + op);
            verify(this.token, this.secret(), {subject: realm, audience: re});
            return Promise.resolve(success(true));
        } catch (e) {
            return Promise.resolve(failure([AbstractAuth.error(e.message)]));
        }
    };
}



export class JWTAuth extends AbstractAuth {
    constructor(protected _secret :any, ) {
        super();
    }

    protected secret() :string {
        return <string>this._secret;
    }

    identify (token :string) :Promise<IIdentityResult> {
        try {
            verify(token, this.secret());
            return Promise.resolve(success(new JWTAuthIdentity(token, this._secret)));
        } catch (e) {
            return Promise.resolve(failure([AbstractAuth.error('bad tokens')]));
        }
    }

    grant(realm :string, ops: string) :Promise<GenericResult<string, IAuthError>> {
        let token = sign({}, this.secret(), {subject: realm, audience: ops});
        return Promise.resolve(success(token));
    }

}
