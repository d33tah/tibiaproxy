"""eval.py

Whenever the user says anything that begins with >, it gets executed as
a line of Python code, with the result being sent back to the player.

The original message does not get forwarded to the server.
"""


def on_client_say(conn, msg):
    """If the message started with >, run it as a Python code."""
    if not msg.startswith(">"):
        return False
    try:
        to_send = str(eval(msg[1:].lstrip()))
    except Exception as e:
        to_send = str(e)
    conn.client_send_said(player={'name': '1', 'level': 1},
                          pos=[96, 123, 7],
                          msg=to_send)
    return True
