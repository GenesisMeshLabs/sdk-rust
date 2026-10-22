# Colour marks for session.txt (docs/assets/render_terminal_gif.py): each
# adds a prefix to a line and leaves its text as recorded.
s/^(Result     : VERIFIED)$/!ok \1/
s/^(exit 0)$/!ok \1/
s/^(exit 1)$/!no \1/
s/^(false)$/!no \1/
s/^(\{.*"manifest_digest_mismatch".*)$/!no \1/
s/^(  ~ .*)$/!dim \1/
