from tls13_session import TLS13Session


def main():
    host = b"cloudflare.com"
    port = 443

    sess = TLS13Session(host, port)
    sess.connect()
    sess.send(b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: curl/7.54.0\r\nAccept: */*\r\n\r\n")
    print(sess.recv().decode())
    sess.close()


if __name__ == "__main__":
    main()
