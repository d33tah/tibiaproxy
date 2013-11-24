tibiaproxy v3.2
===============

Tibia proxy is a proof of concept proxy for OpenTibia servers with protocol
version 10.22. Its goal is to provide you with a server you could run on a
trusted host that you could connect to, tunneling your Tibia session.

Currently its login server code is very buggy, but it relays the game server
packets correctly. It can decode "say" command and - as a proof of concept -
it evaluates whatever the user tried to say and instead of passing it to the
game server, sends it the result of the evaluation. In order to try this out,
begin your message with ">".

WARNING
=======

In case of MMORPG hacks, detection is way simpler than you might think. While
using this application, keep in mind that you might get banned from playing
the game, perhaps even on a per-IP basis. Should this happen, I am IN NO WAY
RESPONSIBLE.

Also, keep in mind that the account name and password is being sent to the
proxy in a basically **UNENCRYPTED** form - it is using the OpenTibia keys,
for which the private key is known. This means that anyone able to sniff the
connection between you and your proxy will be able to see what is your account
name and password, which is a problem if the proxy is not in your local
network.

(sniffing is a real threat and even your neighbor can do that - read up about
ARP spoofing). If your proxy server is hosted on a Unix host, you might want
to try SSH tunneling to add another layer of encryption.

Usage
=====

To be able to run the program, you need Python installed on your system. Once
you have installed it, you need to modify config.py. Please read and follow
the instructions embedded in the file to understand what are the meanings
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
also be sent by proxy. The original world IPs are saved for the next phase.

Then, when a player requests a game server connection, it is greeted with a
fake crypto challenge to provoke a reply. Tibiaproxy makes a connection to the
game server assigned to the requested character and sends the player's reply
with the challenge fixed up. Then, all the communication between the player,
the proxy and the game server is relayed so that the proxy feels invisible -
with the exception that an attempt to say anything will result in printing the
effect of evaluating the message as Python code instead of sending it over to
the server, provided that the message began with ">".

Currently the proxy listens on two ports - one for the login server, one for
game server.

Bugs, problems
==============

Currently, only a small fraction of the Tibia protocol is implemented and none
of the features are guaranteed to work. Also, I received reports about bot
lagging under Windows.

TO-DO list
==========

* clean up the code, add the missing documentation
* investigate the Windows lagging problem
* investigate why sometimes the server message has incorrect length

In the far future, there is a plan to add some record-and-replay/scripting
capabilities and port the proxy to the latest Tibia protocol.

Author, license
===============

This application was written by Jacek Wielemborek <d33tah@gmail.com>. My blog
can be found here: http://deetah.jogger.pl/kategoria/english/

If you're not a viagra vendor, feel free to write me an e-mail, I'd be happy
to hear that you use this program!

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
program with me, under the same license. For details, read the COPYING.txt
file attached to the program.
