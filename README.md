# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!


## Resources
Some resources that will be useful to us when learning about TLS 1.3
*  The Transport Layer Security (TLS) Protocol Version 1.3 [RFC 8446](https://tools.ietf.org/html/rfc8446)
    *  An Interface and Algorithms for Authenticated Encryption [RFC 5116](https://tools.ietf.org/html/rfc5116)
    *  HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869](https://tools.ietf.org/html/rfc5869)
* [Test for TLS 1.3 Support](https://www.cdn77.com/tls-test)
* [TLS 1.3 illustrated](https://tls13.ulfheim.net/)

### Test Endpoint
We want a server that we can make TLS 1.3 requests to and also enable 0-RTT (because I couldn't find a server that supports this...)

### Helpful snippet
```bash
echo -e "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" > request.txt
openssl s_client -connect host.docker.internal:4433 -tls1_3 -sess_out session.pem -ign_eof < request.txt
openssl s_client -connect host.docker.internal:4433 -tls1_3 -sess_in session.pem -early_data request.txt
```

### Testing Container
To test tls1.3 on our own endpoint (couldn't find one with 0-RTT enabled) we will use an instance made by us.

To build:
```bash
cd ./test_server
docker build . -t nginxtls13:latest
```
To run:
```bash
docker run -p4433:443 -it nginxtls13
```

## Goals
 - [x] Send an HTTP GET request to a TLS 1.3 server.
 - [x] Clean up code a bunch!!!
    - [ ] Get a decent code review
 - [ ] Session resumption (0-RTT)

