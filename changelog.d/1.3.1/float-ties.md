### Fixed

- **Floats are written as Python writes them, ties included.** For a float
  exactly halfway between two shortest forms (`13509655414498.0625`),
  `canonical_json` wrote the larger one (`...498.063`) where the reference
  writes the one ending in an even digit (`...498.062`). Such a value in
  signed metadata gave a different canonical form, so an honest record failed
  verification here, and a record this crate signed failed it everywhere
  else. The digits are now exactly Python's `repr`.
