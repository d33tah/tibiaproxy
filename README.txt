tibiaproxy v1.0
===============

Tibia proxy is a proof of concept proxy for OpenTibia servers with protocol
version 8.20. Its goal is to provide you with a server you could run on a
trusted host that you could connect to, tunneling your Tibia session.

Currently its login server code is very buggy, but it relays the game server
packets correctly. It can decode "say" command and - as a proof of concept -
it evaluates whatever the user tried to say and instead of passing it to the
game server, sends it the result of the evaluation.

WARNING
=======

In case of MMORPG hacks, detection is way simpler than you might think. While
using this application, keep in mind that you get banned from playing the game,
perhaps even on a per-IP basis. Should this happen, I am IN NO WAY RESPONSIBLE.

Also, keep in mind that the account name and password is being sent to the
proxy in a basically **UNENCRYPTED** form - it is using the OpenTibia keys, for
which the private key is known. This means that anyone able to sniff the
connection between you and your proxy will be able to see what is your account
name and passwordwhich is a problem if the proxy is not in your local network.

(sniffing is a real threat and even your neighbor can do that - read up about
ARP spoofing). If your proxy server is hosted on a Unix host, you might want
to try SSH tunneling to add another layer of encryption.

Usage
=====

To be able to run the program, you need Python installed on your system. You
might also need to install numpy - since the installation procedures vary
depending on your operating system and I'm too lazy to test it, please consult
your operating system documentation and or type in "easy_install" in your web
search engine.

Once you have installed Python, you need to modify config.py. Please read and
follow theinstructions embedded in the file to understand what are the meanings
of the configuration options.

After configuration, you're free to run main.py. Use any OpenTibia IP changer
to point your Tibia client to the host and IP specified in the config.py and
try to log in using your target server's account name and password.

How does it work?
=================

Short answer: basically, it hardly does at the moment (see "Bugs, problems").
It's currently mostly for demonstration purposes.

Long answer: once launched, the proxy opens a TCP port, listening for Tibia
login connections. When a Tibia client tries to log in, the proxy attempts to
decrypt the message using the OpenTibia key, extracts the XTEA keys from it
and forwards the message to the target server. Then, its reply is being sent
back to the user, with the server IPs changed so that the next connection will
also be sent by proxy.

Then, when a player requests a game server connection, an enormous kludge
begins - in the current version, a connection is made to the login server (in
hope that it also serves game server connections - sometimes it's not true)
and the original packet is simply forwarded (we read the XTEA key, though).
Then, all the communication between the player, the proxy and the game server
is relayed so that the proxy feels invisible - with the exception that an
attempt to say anything will result in printing the effect of evaluating the
message as Python code instead of sending it over to the server.

Bugs, problems
==============

Currently, only a small fraction of the Tibia protocol is implemented and none
of the features are guaranteed to work. At the moment of writing this document,
the proxy tries to forward the modified character list, but it's broken. No
game server proxying is implemented yet (though this document might be
outdated).

TO-DO list
==========

In the future, there is a plan to add some record-and-replay/scripting
capabilities and port the proxy to the latest Tibia protocol.

Author, license
===============

This application was written by Jacek Wielemborek <d33tah@gmail.com>. My blog
can be found here:
[http://deetah.jogger.pl/kategoria/english/](http://deetah.jogger.pl/kategoria/english/)

If you're not a viagra vendor, feel free to write me an e-mail, I'd be happy to
hear that you use this program!

This program is Free Software and is protected by GNU General Public License
version 3. Basically, it gives you four freedoms:


Freedom 0: The freedom to run the program for any purpose.

Freedom 1: The freedom to study how the program works, and change it to make
    it do what you wish.

Freedom 2: The freedom to redistribute copies so you can help your neighbor.

Freedom 3: The freedom to improve the program, and release your improvements
    (and modified versions in general) to the public, so that the whole
     community benefits.

In order to protect that freedom, you must share any changes you did to the
program with me, under the same license. For details, read the COPYING.txt file
attached to the program.
