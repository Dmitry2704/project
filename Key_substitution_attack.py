g = {'option': 'get_signature'}
    s.send(json.dumps(g).encode() + b'\n')
    data = s.recv(4096)
    response = json.loads(data)
    N = int(response['N'], 16)
    e = int(response['e'], 16)
    SIGNATURE = int(response['signature'], 16)

    # Перебираем разные сообщения
    for i in range(1, 10000):
        msg = f"I am Mallory{' ' * i}own CryptoHack.org"
        DIGEST_new = bytes_to_long(emsa_pkcs1_v15.encode(msg.encode(), 256))

        if 0 < DIGEST_new < SIGNATURE:
            n_my = SIGNATURE - DIGEST_new
            g = {'option': 'verify', 'N': hex(n_my), 'e': hex(1), 'msg': msg}
            s.send(json.dumps(g).encode() + b'\n')
            data = s.recv(4096)
            print(data)
            break
