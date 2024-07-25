# Instruções

Como criptoanalista no Biuro Szyfrów, você interceptou uma mensagem cifrada,
criptografada com AES 256 bits, cuja chave (presente no arquivo
key_for_message.en) foi criptografada utilizando uma chave pública RSA. Você
adquiriu a chave pública, mas ela está encriptada com AES256 também! Você
enviou um dos seus melhores agentes para obter essa chave, mas dos doze
caracteres da senha, ele descobriu apenas os dois primeiros: "an", antes de ser
capturado. Em sua última transmissão, ele conseguiu lhe enviar a hash da senha
(presente no arquivo key_for_rsa_public.hash). Muito provavelmente foi
utilizado um algoritmo de hash famoso para ocultar a senha...

Você tem acesso aos seguintes items: mensagem cifrada, chave usada para
encriptar a mensagem (mas encriptada), chave pública RSA (mas encriptada), e
hash da chave utilizada para encriptar a chave pública.

Sabe ainda que provavelmente foi utilizado o programa openssl para realizar as
encriptações.

# 1. Quebrar `key_for_rsa_public.hash`

obter a hash no formato hex

```sh
openssl base64 -d -in key_for_rsa_public.hash | xxd -p
```

quebrar a hash com `hashcat`

```sh
hashcat \
 --optimized-kernel-enable \
 --workload-profile 4 \
 --hash-type 1400 \
 --attack-mode 3 \
 4dc207a086d24bcd29125d39adbb17190464f0aa259bc6a5f7c367cd36594df1 \
 'an?l?l?l?l?l?l?l?l?l?l'
```

10 horas depois....

```txt
4dc207a086d24bcd29125d39adbb17190464f0aa259bc6a5f7c367cd36594df1:andrejkarpat

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 4dc207a086d24bcd29125d39adbb17190464f0aa259bc6a5f7c...594df1
Time.Started.....: Tue Jul 23 21:59:58 2024 (9 hours, 21 mins)
Time.Estimated...: Wed Jul 24 07:21:37 2024 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Mask.......: an?3?3?3?3?3?3?3?3?3?3 [12]
Guess.Charset....: -1 Undefined, -2 Undefined, -3 ?l, -4 Undefined
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 867.7 MH/s (351.18ms) @ Accel:1024 Loops:676 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 27710136516608/141167095653376 (19.63%)
Rejected.........: 0/27710136516608 (0.00%)
Restore.Point....: 40990867456/208827064576 (19.63%)
Restore.Sub.#1...: Salt:0 Amplifier:0-676 Iteration:0-676
Candidate.Engine.: Device Generator
Candidates.#1....: angeyvkulpat -> anqfbmvyswnt
Hardware.Mon.SMC.: Fan0: 40%, Fan1: 40%
Hardware.Mon.#1..: Util:100%

Started: Tue Jul 23 21:59:52 2024
Stopped: Wed Jul 24 07:21:38 2024
```

# 2. Descriptografar `key_public.en`

```sh
openssl base64 -decrypt -in key_public.en -out key_public.bin
openssl aes256 -in key_public.bin -pass pass:andrejkarpat -out key_public.pem
```

# 3. Descriptografar `key_for_message.en`

Com a chave pública obtida no passo anterior, conseguimos descobrir `n`, e `e`
usando o [dcode.fr](https://www.dcode.fr/rsa-cipher). Agora precisamos fatorar
`n` para descobrir `p` e `q`, e com isso gerar a chave privada.

Vamos usar o [cado-nfs](https://gitlab.inria.fr/cado-nfs/cado-nfs) para fatorar.

```sh
./cado-nfs.py 26179751854087331402331071604988485626982836276798177195222446151071273439780592994270737435017138406631242790569709
```

48 minutos depois...

```txt
Info:Complete Factorization / Discrete logarithm: Total cpu/elapsed time for entire Complete Factorization 17004.2/2921.35
5146951772184269300025961189405010212772342675599485312661 5086457579721431558131968975470302984140630429995118930169
```

Agora conseguimos gerar a chave privada usando o [PyCryptodome](https://github.com/Legrandin/pycryptodome)

```python
from Crypto.PublicKey import RSA


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    assert g != 1, "modular inverse does not exist"
    return x % m


e = 65537
p = 5146951772184269300025961189405010212772342675599485312661
q = 5086457579721431558131968975470302984140630429995118930169

n = p * q
d = modinv(e, (p - 1) * (q - 1))

private_key = RSA.construct((n, e, d))

with open("key_private.pem", "wb") as f:
    f.write(private_key.exportKey())
```

E agora finalmente conseguimos descriptografar `key_for_message.en` utilizando a
chave privada gerada.

```sh
openssl pkeyutl -decrypt -inkey key_private.pem -in key_for_message.en
```

E com isso obtemos a chave `meirefortuna`.

# 4. Descriptografar `message.en`

```sh
openssl aes256 -decrypt -nosalt -base64 -in message.en -pass pass:meirefortuna -out message.txt
```
