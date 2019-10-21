# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!


## Resources
Some resources that will be useful to us when learning about TLS 1.3
*  The Transport Layer Security (TLS) Protocol Version 1.3 [RFC 8446](https://tools.ietf.org/html/rfc8446)
    *  An Interface and Algorithms for Authenticated Encryption [RFC 5116](https://tools.ietf.org/html/rfc5116)
    *  HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869](https://tools.ietf.org/html/rfc5869)
* [Test for TLS 1.3 Support](https://www.cdn77.com/tls-test)
* [TLS 1.3 illustrated](https://tls13.ulfheim.net/)


## Goals
 - [x] Send an HTTP GET request to a TLS 1.3 server.
 - [x] Clean up code a bunch!!!
    - [ ] Get a decent code review
 - [ ] Once we have a client that can send a HTTP Get Request we will want to create a server.
 - [ ] Once we've created a client and a server we may want to look into creating an HTTP proxy that supports TLS 1.3

