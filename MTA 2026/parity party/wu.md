# Parity Party

## Thông tin challenge

- Chủ đề: Crypto, RSA
- Lỗ hổng: RSA parity oracle
- Flag: `MTA60{par1ty_p4rty_1s_n0t_s0_easy}`

## Phân tích mã nguồn

Mã nguồn của challenge:

```py
import sys
from Crypto.Util.number import getPrime, bytes_to_long
import os

flag = os.getenv('FLAG', 'flag{fake_flag}').encode()

def generate_keys():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = 65537
    d = pow(e, -1, (p-1) * (q-1))
    return (n, e), d

def main():
    pub, priv = generate_keys()
    n, e = pub
    d = priv

    m = bytes_to_long(flag)
    c = pow(m, e, n)

    print(f"N = {n}")
    print(f"e = {e}")
    print(f"flag_enc = {c}")

    for i in range(1024):
        try:
            user_input = input(f"[{i+1}/1024] Enter ciphertext (integer): ")
            ct = int(user_input)
            pt = pow(ct, d, n)
            
            print(f"Parity: {pt % 2}")
            
        except ValueError:
            print("Invalid input.")
            break
        except EOFError:
            break

if __name__ == "__main__":
    main()
```

Challenge sinh khóa RSA với hai số nguyên tố 512 bit:

```python
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
d = pow(e, -1, (p-1) * (q-1))
```

Sau đó chương trình mã hóa flag:

```python
m = bytes_to_long(flag)
c = pow(m, e, n)
```

Server in ra `N`, `e`, `flag_enc`, rồi cho phép người dùng gửi tối đa 1024 ciphertext bất kỳ. Với mỗi ciphertext `ct`, server giải mã bằng private key và trả về bit chẵn lẻ của plaintext:

```python
pt = pow(ct, d, n)
print(f"Parity: {pt % 2}")
```

Do server cho phép giải mã ciphertext do người dùng chọn và tiết lộ `pt % 2`, đây là một parity oracle. RSA không có padding và có tính nhân:

```text
Enc(a) * Enc(b) mod N = Enc(a * b mod N)
```

Vì vậy có thể nhân ciphertext của flag với `2^e mod N` nhiều lần để hỏi oracle về tính chẵn lẻ của:

```text
2m mod N
4m mod N
8m mod N
...
```

Thông tin chẵn lẻ này đủ để thu hẹp khoảng giá trị của plaintext `m`.

## Ý tưởng khai thác

Ban đầu ta biết:

```text
0 <= m < N
```

Gửi ciphertext:

```text
c1 = c * 2^e mod N
```

Server giải mã:

```text
c1^d mod N = 2m mod N
```

Vì `N` là tích của hai số nguyên tố lẻ nên `N` lẻ.

- Nếu `2m mod N` chẵn, suy ra `2m < N`, tức là `m < N/2`.
- Nếu `2m mod N` lẻ, suy ra `2m >= N`, tức là phép trừ `N` đã xảy ra và `m >= N/2`.

Như vậy, một bit parity giúp chia đôi khoảng chứa plaintext. Tiếp tục nhân ciphertext hiện tại với `2^e mod N` và hỏi oracle, mỗi lần lại chia đôi khoảng `[low, high]`. Sau khoảng `bit_length(N)` lần, khoảng này đủ nhỏ để khôi phục chính xác `m`.

Với challenge này, `N` dài 1024 bit và server cho 1024 lượt hỏi, vừa đủ để thực hiện tấn công.

## Script khai thác

```python
#!/usr/bin/env python3
from fractions import Fraction
import re
import socket


HOST = "mta-ctf-60.id.vn"
PORT = 6002


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError(data.decode(errors="replace"))
        data += chunk
    return data.decode(errors="replace")


def main():
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        banner = recv_until(sock, b"Enter ciphertext (integer): ")
        n = int(re.search(r"N = (\d+)", banner).group(1))
        e = int(re.search(r"e = (\d+)", banner).group(1))
        c = int(re.search(r"flag_enc = (\d+)", banner).group(1))

        multiplier = pow(2, e, n)
        ct = c
        low = Fraction(0)
        high = Fraction(n)

        for _ in range(n.bit_length()):
            ct = (ct * multiplier) % n
            sock.sendall(f"{ct}\n".encode())
            response = recv_until(sock, b"Enter ciphertext (integer): ")
            parity = int(re.search(r"Parity: ([01])", response).group(1))

            mid = (low + high) / 2
            if parity == 0:
                high = mid
            else:
                low = mid

        for candidate in range(int(low) - 4, int(high) + 8):
            if candidate <= 0:
                continue
            raw = candidate.to_bytes((candidate.bit_length() + 7) // 8, "big")
            flag = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", raw)
            if flag:
                print(flag.group(0).decode(errors="replace"))
                return

        recovered = int(high)
        raw = recovered.to_bytes((recovered.bit_length() + 7) // 8, "big")
        print(raw.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

Chạy script sẽ thu được kết quả mong muốn.

## Flag

```text
MTA60{par1ty_p4rty_1s_n0t_s0_easy}
```
