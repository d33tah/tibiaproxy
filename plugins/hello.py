def on_client_say(conn, msg):
    if msg != "hello world":
        return False

    to_send = "yeah, hi!"
    conn.client_send_said(player={'name': '1', 'level': 1},
                          pos=[96, 123, 7],
                          msg=to_send)

    return True
