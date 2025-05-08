---
title: 'Wizer CTF - Accidentally Bug Hunting a CTF'
description: 'How I acidentally discovered a bug in the infrastructure for Wizer CTF '
pubDate: 'Feb 7 2024'
heroImage: '/blog-placeholder-2.jpg'
---

During the Wizer 6-hour Blitz CTF, I discovered an interesting error message behaviour after trying to submit the flag for challenge 4.
This error technically allowed me to solve challenge 4 and 5 without solving the challenge at all!
This post is about how I found it, how it worked, and what I did when I found it.

## Discovery
After having solved challenge 4, titled "Profile page" I went to submit the flag using the CTF platform. I was, however, a bit confused as to how the submitting worked, as it was my first flag on the platform, so I did a test submit just to see how it worked:
![CTF dashboard after submitting test](/src/assets/WizerBug/TestSubmit.png)

I then proceeded to submit the actual flag by replacing ``test`` with the flag ``WIZER{'PICKL1NG_1S_DANGEROUS'}``, so the URL became:
> ``https://dsw3qg.wizer-ctf.com/submit_flag/WIZER{'PICKL1NG_1S_DANGEROUS'}``

But then I stopped for a moment because I noticed that it just told me ``Close to hackin' it, alert needs to show WIZER{'PICKL1NG_1S_DANGEROUS'}``:
![Highlighted flag in error message](/src/assets/WizerBug/TestFlagHighlight.png)

So it told me the flag directly by simply making it error by giving it anything other than the flag?

I had a hard time believing this was the case, so I started looking at the other challenges and noticed that challenge 5 is structured the same way with the ``submit_flag`` endpoint.
I then decided to see if it had the same behaviour, and sure enough, it gave me the flag for challenge 5 without even solving it by submitting ``test``.
To be completely certain, this was not intended behaviour and was the actual flag I tried to submit it:
![Challenge 5 solved](/src/assets/WizerBug/Chall5Blood.png)

And it worked! I had successfully solved and first blooded challenge 5 without even looking at it.

I knew this was bad and would be an extremely unfair advantage to be able to solve a third of the challenges without even trying, so I decided to immediately bring my proof to the admins to get it fixed as soon as possible.

## Remediation
After becoming certain that this was an unintended and "game-breaking" issue, I immediately started explaining the situation to an admin and also asked them to remove my solve for challenge 5, so it could be first blooded fairly. Their reaction when hearing about the issue was simply:
> "Oh god"

They were, however, very cooperative, thankful, and quick at fixing the issue, which I really appreciate. Within just a few minutes, the error message had been changed and my "fake" solve reverted. Luckily, it did not seem like anyone else noticed or abused this bug before it was fixed.

Small bugs like this can very easily happen, and I highly suggest that you report them if you ever come across anything similar. The admins will definitely be really thankful for being informed about it.

Many thanks to [PinkDraconian](https://www.linkedin.com/in/robbe-van-roey/) and the entire team at [Wizer](https://www.wizer-training.com) for not only hosting an amazing event but also being very nice, responsive, and cooperative about fixing the bug!