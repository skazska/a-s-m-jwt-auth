import "mocha";
import {expect, use}  from 'chai';
// import sinonChai = require("sinon-chai");
import {JWTAuth} from "../src/authenticator";
import {RegExIdentity, IAuthIdentity} from "@skazska/abstract-service-model";
// use(sinonChai);

describe('auth', () => {
    let instance :JWTAuth = null;
    let token :string;
    let identity :IAuthIdentity;
    before(() => {
        instance = new JWTAuth(RegExIdentity.getInstance, {secretSource: 'secret'});
    });
    it('constructor produce instance with expected properties and methods', () => {
        expect(instance).to.have.property('identify').which.is.a('function');
        expect(instance).to.have.property('grant').which.is.a('function');
    });
    it('#grant returns success with token', async () => {
        let tokenResult = await instance.grant({a: 'read', b: 'x.*'}, 'user');
        token = tokenResult.get();
        expect(token).to.be.a('string');
    });

    it('#identify returns failure on wrong token', async () => {
        let identityResult = await instance.identify('wrong');
        expect(identityResult.isFailure).to.be.true;
        expect(identityResult.errors[0].message).equal('bad tokens');
    });

    it('#identify returns success with instance of IAuthIdentity and has method access and property subject', async () => {
        let identityResult = await instance.identify(token);
        identity = identityResult.get();
        expect(identity).to.have.property('access').which.is.a('function');
        expect(identity).to.have.property('subject').which.equals('user');
    });
    it('#IAuthIdentity access method ', async () => {
        expect(identity.access('a', 'read').get()).to.be.true;
        expect(identity.access('a', 'write').isFailure).to.be.true;
        expect(identity.access('b', 'xwrite').get()).to.be.true;
        expect(identity.access('b', 'ywrite').isFailure).to.be.true;
    });
    it('#grant with realms returns success with token', async () => {
        let tokenResult = await instance.grant({a: 'read', b: 'x.*'}, 'user', ['r1']);
        token = tokenResult.get();
        expect(token).to.be.a('string');
    });

    it('#identify returns failure on wrong realm', async () => {
        let identityResult = await instance.identify(token, 'r2');
        expect(identityResult.isFailure).to.be.true;
        expect(identityResult.errors[0].message).equal('bad tokens');
    });

    it('#identify returns success with instance of IAuthIdentity and has method access and property subject', async () => {
        let identityResult = await instance.identify(token, 'r1');
        identity = identityResult.get();
        expect(identity).to.have.property('access').which.is.a('function');
        expect(identity).to.have.property('subject').which.equals('user');
    });

    it('#IAuthIdentity access method ', async () => {
        expect(identity.access('a', 'read').get()).to.be.true;
        expect(identity.access('a', 'write').isFailure).to.be.true;
        expect(identity.access('b', 'xwrite').get()).to.be.true;
        expect(identity.access('b', 'ywrite').isFailure).to.be.true;
    });

});
