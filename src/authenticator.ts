/**
 * JWT authentication module
 */

import {
    AbstractAuth,
    IAuthError,
    IAuthIdentity,
    IAccessDetails,
    failure,
    success,
    GenericResult,
    IAuthData,
    IAuthOptions,
    IAuthIdentityOptions,
    IAuthGrantOptions,
    IAuthVerifyOptions,
    IAbstractAuthIdentifyOptions
} from "@skazska/abstract-service-model";
import {verify, sign, SignOptions, VerifyOptions} from "jsonwebtoken";

interface IJWTData {
    sub: string,
    aud: string[],
    data: any
}

/**
 * JWT Auth constructor module
 */
export interface IJWTAuthOptions extends IAuthOptions {

}

export class JWTAuth extends AbstractAuth {
    /**
     * @param identityConstructor
     * @param options
     */
    constructor(
        identityConstructor :(subject :string, details :IAccessDetails, options? :IAuthIdentityOptions) => IAuthIdentity,
        options?: IJWTAuthOptions
    ) {
        super(identityConstructor, options);
    }

    /**
     * checks token and returns auth data
     * @param secret - secret to use
     * @param token - token
     * @param options
     */
    protected verify(secret: any, token: string, options?: VerifyOptions): Promise<GenericResult<IAuthData>> {
        try {
            let content = <IJWTData>verify(token, secret, options);
            return Promise.resolve(success({subject: content.sub, details: content.data}));
        } catch (e) {
            return Promise.resolve(failure([AbstractAuth.error('bad tokens')]));
        }
    }

    /**
     * generates token
     * @param details - auth details
     * @param subject - subject
     * @param options
     */
    async grant(details: any, subject :string, options?: SignOptions) :Promise<GenericResult<string>> {
        try {
            let secret = await this.secret();
            if (secret.isFailure) return secret.asFailure();

            let token = sign({data: details}, secret.get(), {subject: subject, ...options});
            return Promise.resolve(success(token));
        } catch (e) {
            return Promise.resolve(failure([e]));
        }
    }
}
