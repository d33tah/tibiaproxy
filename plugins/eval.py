def on_client_say(conn, msg):
    if not msg.startswith(">"):
        return False
    try:
        to_send = str(eval(msg[1:].lstrip()))
    except Exception, e:
        to_send = str(e)
    conn.client_send_said(player={'name': '1', 'level': 1},
                          pos=[96, 123, 7],
                          msg=to_send)
    return True
