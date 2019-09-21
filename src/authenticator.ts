import {
    AbstractAuth,
    IAuthError,
    IAuthIdentity,
    IAccessDetails,
    failure,
    success,
    GenericResult,
    IAuthData,
    IAuthOptions
} from "@skazska/abstract-service-model";
import {verify, sign} from "jsonwebtoken";

/**
 * JWT authentication module
 */

interface IJWTData {
    sub: string,
    aud: string[],
    data: any
}

export class JWTAuth extends AbstractAuth {
    /**
     * @param identityConstructor
     * @param options
     */
    constructor(
        identityConstructor :(subject :string, details :IAccessDetails, realm? :string) => IAuthIdentity,
        options?: IAuthOptions
    ) {
        super(identityConstructor, options);
    }

    /**
     * checks token and returns auth data
     * @param secret - secret to use
     * @param token - token
     * @param realm - realm to check
     */
    protected verify(secret: any, token: string, realm?: string): Promise<GenericResult<IAuthData>> {
        try {
            let content = <IJWTData>verify(token, secret, {audience: realm});
            return Promise.resolve(success({subject: content.sub, details: content.data, realms: content.aud}));
        } catch (e) {
            return Promise.resolve(failure([AbstractAuth.error('bad tokens')]));
        }
    }

    /**
     * generates token
     * @param details - auth details
     * @param subject - subject
     * @param realms - realms
     */
    async grant(details: any, subject :string, realms?: string[]) :Promise<GenericResult<string>> {
        try {
            let secret = await this.secret();
            if (secret.isFailure) return secret.asFailure();

            let token = sign({data: details}, secret.get(), {subject: subject, audience: realms || []});
            return Promise.resolve(success(token));
        } catch (e) {
            return Promise.resolve(failure([e]));
        }
    }

}
