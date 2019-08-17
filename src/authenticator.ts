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

//TODO this is to implement later

interface IJWTData {
    sub: string,
    aud: string[],
    data: any
}

export class JWTAuth extends AbstractAuth {
    constructor(
        identityConstructor :(subject :string, details :IAccessDetails, realm? :string) => IAuthIdentity,
        options?: IAuthOptions
    ) {
        super(identityConstructor, options);
    }

    protected verify(secret: any, token: string, realm?: string): Promise<GenericResult<IAuthData, IAuthError>> {
        try {
            let content = <IJWTData>verify(token, secret, {audience: realm});
            return Promise.resolve(success({subject: content.sub, details: content.data, realms: content.aud}));
        } catch (e) {
            return Promise.resolve(failure([AbstractAuth.error('bad tokens')]));
        }
    }

    async grant(details: any, subject :string, realms?: string[]) :Promise<GenericResult<string, IAuthError>> {
        try {
            let secret = await this.secret();
            if (secret.isFailure) return failure(secret.errors);

            let token = sign({data: details}, secret.get(), {subject: subject, audience: realms || []});
            return Promise.resolve(success(token));
        } catch (e) {
            return Promise.resolve(failure([e]));
        }
    }

}
