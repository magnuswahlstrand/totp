import * as crypto from "crypto"
import * as base32 from "hi-base32";

export function hmac_sha_1(secret: string, counter: number) {
    // Counter should be 8-byte value, according to spec
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    view.setUint32(4, counter)
    return crypto.createHmac("sha1", secret)
        .update(view)
        .digest()
}

export function hotp(secret: string, counter: number, digits = 6) {
    const hmacResult = hmac_sha_1(secret, counter)

    // From https://datatracker.ietf.org/doc/html/rfc4226#section-5.4
    const offset = hmacResult[19] & 0xf
    const dynamicBinaryCode = (hmacResult[offset] & 0x7f) << 24
        | (hmacResult[offset + 1] & 0xff) << 16
        | (hmacResult[offset + 2] & 0xff) << 8
        | (hmacResult[offset + 3] & 0xff);

    return dynamicBinaryCode % (10 ** digits)
}


export const counterFromDate = (now: number, time_step = 30) => {
    return Math.trunc(now / (time_step * 1000));
}


export function totp(secret: string, time_step = 30, digits = 6) {
    const counter = counterFromDate(Date.now(), time_step)
    return hotp(secret, counter, digits)
}

export function generate_url() {
    const ISSUER = "32 Bytes AB"
    const user = "magnus@wahlstrand.dev"

    // Generate secret
    // const secret = v4()
    const secretEncoded = base32.encode("12345678901234567890")
    // const secretEncoded = "12345678901234567890")

    return {uri: `otpauth://totp/${ISSUER}:${user}?secret=${secretEncoded}&issuer=${ISSUER}`};
}
