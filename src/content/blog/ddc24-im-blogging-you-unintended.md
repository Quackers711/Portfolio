---
title: 'DDC24 - im-blogging-you unintended'
description: 'CTF writeup detailing the unintended solution for im-blogging-you during DDC 2024.'
pubDate: 'Mar 18 2024'
heroImage: '/blog-placeholder-3.jpg'
tags: ['CTF', 'DDC', 'Web', 'Unintended']
---

## Intro

This web challenge was rated hard and had 8 solves in the junior category. The intended solution is getting SQLi in a search field, leaking all posts, cracking a bcrypt hashed password from a hidden post, and logging in as this user. However, the challenge design introduced a rather unfortunate issue that allowed me to bypass the entire challenge and get the flag.

## Unintended Solution

When you first load up the challenge and visit the website, you are greeted with the main blog page:
![Main blog page](/src/assets/DDC24Blog/MainFeed.jpg)
The most notable features are the login/register functions and the main "post feed." There is also a search bar to search posts if we log in, but we will not need that function for this solution.

We simply start by registering a new account on the page and logging in:
![Login page](/src/assets/DDC24Blog/Login.png)

> Be sure to tick "remember me". This is vital for this to work

After logging in and going to our account page at http://im-blogging.hkn/account, we are greeted by our account:
![Our account page](/src/assets/DDC24Blog/OurAcc.jpg)

If we open our browser cookies and check our session token, we can see which user ID we have. To do this, we simply have to decode it using ``flask-unsign``:<br>
``flask-unsign --decode --cookie ".eJwljkFqQzEMRO_idRaWLMlWLvOxZImWQAv_J6uQu9fQ1TDDG3jvcuQZ11e5P89X3Mrxvcq9kBqZIbsxtkinlUbQZwLW5AhjWKtXSo8BYABOTQmpCnqsjajsJAytMYZ7YiCggQAkM866NAY3yBFtGs7sgc7ZmVYddUHZIq8rzn8bkN39OvN4_j7iZy_TtbvqtGbKUyu0Ibaf6sIyRTKJiLOVzx-r9z_9.ZfmDzA.ICEjIDrnqSrSxDNYbMpAXHMkURM"``

Which returns:
```
{'_fresh': True, '_id': '49b4bb25cb523efc4dfb417af120f5eeb51dd704fce811b11c439424062ced0f596ced42e90e88ccf2e212b1611f552a0d9e8531f8e3ab2af7e2c5f754d080d1', '_user_id': '16', 'csrf_token': 'ac97c99ab3b95a901386b0809c656a66ff4445f3'}
```

Here we can see that our user ID is 16, which will be very important as to why this works later.

Now that we are logged in, have ticked the remember-me button, and have navigated to the account page, we simply need to reset the challenge on the challenge platform:

![Reset button on Haaukins](/src/assets/DDC24Blog/ResetButton.png)

After this is done and we give the challenge a few seconds to load up again, we can refresh our browser with the account page and see that we are now logged in as a different user:
![Random account we have logged in as](/src/assets/DDC24Blog/Acc1.jpg)

And this is the core concept for unintentionally getting the flag. Simply keep resetting the challenge until we are logged in as the user that has the flag. This took me about 4 tries when trying to replicate it, but I accidentally got it on my first try during the competition, which is also the only reason I was able to find it.

After a couple of tries, we are eventually logged in as the flag user:
![Flag user logged in](/src/assets/DDC24Blog/Flag.jpg)

And we have our flag!<br>
``DDC{MY_S0NS_N4M3_1S_B0BBY_T4BL3S}``


## Challenge Design - Why this was possible
After the competition, an admin was so kind to share some information on how the challenge worked behind the scenes and why this unintended solution is possible.

The basic setup is as follows:
1. Generate an admin account (This is not relevant for solving the challenge)
2. Generate a random amount of filler accounts between 12-20
3. Generate Bobby Tables - The account with the flag

So, the reason this works is because it generates a random number of accounts each time and puts the flag account as the last one. Therefore, it is possible to obtain a cookie that authorizes an ID that is then later assigned to a different user. This is why it is important that our first ID is under 20.

For example, we have the ID 16. When we sign up, there are a total of 15 users, and then the account we create. But once we reset the challenge, the accounts get generated again, and our account disappears, except we have the authorization cookie for ID 16, meaning we have access to that user. So then we just reset until we are lucky enough that it creates the admin account and 14 filler accounts, so that the 16th account, which we have access to, becomes the flag account, Bobby Tables.