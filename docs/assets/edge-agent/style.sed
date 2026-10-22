# Colour marks for session.txt (docs/assets/render_terminal_gif.py): each
# adds a prefix to a line and leaves its text as recorded.
s/^(\{"allowed":true)/!ok \1/
s/^(\{"allowed":false)/!no \1/
s/^(exit 0)$/!ok \1/
s/^(\{"connected":true.*"pending_uploads":0.*)$/!ok \1/
s/^(\{"record_kind")/!dim \1/
