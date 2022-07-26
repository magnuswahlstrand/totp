import {expect, test} from "vitest";
import {counterFromDate, generate_url, hmac_sha_1, hotp, totp} from "./totp";


const SECRET = "12345678901234567890"

const hmacCases = [
    {count: 0, expected: "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
    {count: 1, expected: "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
    {count: 2, expected: "0bacb7fa082fef30782211938bc1c5e70416ff44"},
    {count: 3, expected: "66c28227d03a2d5529262ff016a1e6ef76557ece"},
    {count: 4, expected: "a904c900a64b35909874b33e61c5938a8e15ed1c"},
    {count: 5, expected: "a37e783d7b7233c083d4f62926c7a25f238d0316"},
    {count: 6, expected: "bc9cd28561042c83f219324d3c607256c03272ae"},
    {count: 7, expected: "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
    {count: 8, expected: "1b3c89f65e6c9e883012052823443f048b4332db"},
    {count: 9, expected: "1637409809a679dc698207310c8c7fc07290d9e5"},
]

test.each(hmacCases)("HMAC (%s) should be %s", (tc) => {
    const hex = hmac_sha_1(SECRET, tc.count).toString('hex')
    expect(hex).toBe(tc.expected)
});


const offsetCases = [
    {count: 1, expected: 0xb}, // "75a48a19d4cbe100644e8ac1397eea747a2d33ab"
    {count: 2, expected: 0x4} // "0bacb7fa082fef30782211938bc1c5e70416ff44"
]

// Verify that the offset calculation is OK
test.each(offsetCases)("offset (%s) should be %s", (tc) => {
    const digest = hmac_sha_1(SECRET, tc.count)
    const offset = digest[19] & 0xf
    expect(offset).toBe(tc.expected)
})

// From https://datatracker.ietf.org/doc/html/rfc4226#page-32
const otpCases = [
    {count: 0, expected: 755224},
    {count: 1, expected: 287082},
    {count: 2, expected: 359152},
    {count: 3, expected: 969429},
    {count: 4, expected: 338314},
    {count: 5, expected: 254676},
    {count: 6, expected: 287922},
    {count: 7, expected: 162583},
    {count: 8, expected: 399871},
    {count: 9, expected: 520489},
]

test.each(otpCases)("HOTP (%s) should be %s", (tc) => {
    const otp = hotp(SECRET, tc.count)
    expect(otp).toBe(tc.expected)
});

const totpCases = [
    {date: "2022-07-26T21:59:40", expected: 607601},
    {date: "2022-07-26T22:00:10", expected: 825946},
    {date: "2022-07-26T22:00:40", expected: 903318},
    {date: "2022-07-26T22:01:10", expected: 154355},
]



test.each(totpCases)("TOTP (%s) should be %s", (tc) => {
    const otp = hotp(SECRET, counterFromDate(new Date(tc.date).getTime()))
    expect(otp).toBe(tc.expected)
});


test("TOTP (%s) should be %s", (tc) => {
    console.log(totp(SECRET))
    console.log(generate_url())
});



new Date("2022-07-26T20:50:00");
