WordPress Group Overseer
========================

A simple mu-plugin to do role and resource synchronization with Conext.

Modus operandi
--------------

For now, here's a dramatically unappealing diagram (it should get the message across, though).

Stuff you should know but may not be obivous from the lovely picture:

* Overseer works INSIDE of Wordpress. It's a plugin. It works as part of WP.
* Grouper and Regroup are external applications, HTTPS requests are made to fetch data.
* Alice is [probably](http://en.wikipedia.org/wiki/On_the_Internet,_nobody_knows_you're_a_dog) human. 
* Before Wordpress starts talking to the Overseer, it does a SAML login (redirecting to engineblock, etc) via Conext.

![plain_diagram](http://i.imgur.com/nw1NQHL.png "The ways of the Overseer")

(Did it feel like a thousand words?)
