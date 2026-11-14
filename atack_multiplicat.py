g = {'option': 'get_pubkey'}
    s.send(json.dumps(g).encode() + b'\n')
    data = s.recv(4096)
    data = json.loads(data)
    n = int(data['N'], 16)
    e = int(data['e'], 16)

    # Вычисляем B
    S = b"admin=True"
    admin_int = bytes_to_long(S)
    inv2 = pow(2, -1, n)
    B = (admin_int * inv2) % n

    # Подписываем B
    g = {'option': 'sign', 'msg': hex(B)[2:]}
    s.send(json.dumps(g).encode() + b'\n')
    data = json.loads(s.recv(4096))
    sig_B = int(data['signature'], 16)

    # Подписываем 2
    g = {'option': 'sign', 'msg': '02'}
    s.send(json.dumps(g).encode() + b'\n')
    data = json.loads(s.recv(4096))
    sig_2 = int(data['signature'], 16)

    # Комбинируем подписи
    admin_signature = (sig_B * sig_2) % n

    # Верифицируем
    g = {
        "option": "verify",
        "msg": "61646d696e3d54727565",  # hex от b"admin=True"
        "signature": hex(admin_signature)
    }
    s.send(json.dumps(g).encode() + b'\n')
    data = json.loads(s.recv(4096))
    print(data)
