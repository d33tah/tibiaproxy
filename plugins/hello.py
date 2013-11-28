"""hello.py

If the user says "hello world", a message "yeah, hi" is sent back to him.

The original message does not get forwarded to the server.
"""


def on_client_say(conn, msg):
    """Send "yeah, hi" if user said "hello world"."""
    if msg != "hello world":
        return False

    to_send = "yeah, hi!"
    conn.client_send_said(player={'name': '1', 'level': 1},
                          pos=[96, 123, 7],
                          msg=to_send)

    return True
