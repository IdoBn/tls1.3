# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!


## TLS 1.3 HTTP Get Request
First thing's first we want to find a server that will be able to answer a TLS 1.3 HTTP Get request.

Using https://www.cdn77.com/tls-test we tested www.cloudflare.com for TLS 1.3 support and it looks like it supports TLS 1.3. 

We want to be able to test the curl server so we will need a curl clinet for this we will need to compile curl from source because on mac os it doesn't come pre compiled to support TLS 1.3. See this site for how to compile curl on mac os https://curl.haxx.se/mail/lib-2002-01/0019.html

A site that will be super helpful during our development is [TLS 1.3 illustrated](https://tls13.ulfheim.net/)


## Goals
 1. Send an HTTP GET request to a TLS 1.3 server.
 2. Once we have a client that can send a HTTP Get Request we will want to create a server.
 3. Once we've created a client and a server we may want to look into creating an HTTP proxy that supports TLS 1.3
