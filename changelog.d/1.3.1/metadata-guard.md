### Fixed

- **Observations and break-glass records are guarded exactly as the NA
  guards them.** The secret guard now applies the reference's
  `metadata_problem`. It covers an observation's `actor`, `source_event_id` and
  `version_id` with its `metadata`, and a break-glass record's justification
  with its parameters, attributes and outcome detail. It counts their size as
  the NA does: text outside ASCII escaped (`é` is six bytes, an emoji twelve)
  and floats in Python's form. Before, such a record was signed after its
  action ran, then refused for good (`*_secret_material`) and dead-lettered.
  Now it is refused before signing. `governed_action_with_break_glass` keeps
  room for the report measured the same way before the action runs. A report
  that leaves no room with the justification is left out of the record
  (`dropped`), which is still kept.
- A string ending in a newline is checked as the reference checks it: a token
  or key followed by `\n` is refused as secret material, as the NA refuses it.
