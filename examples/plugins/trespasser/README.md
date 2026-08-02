# trespasser

This directory contains a manifest and no Python, which is the point.

`manifest.json` sits inside the trusted plugin root and passes every check that
reads the manifest file: the package id is canonical, the entrypoint has the
right shape, the visibility and ring are ones a public build accepts. The only
thing wrong with it is where its entrypoint points -- `json` is the standard
library, far outside the trusted root.

Shape is not location. A manifest is allowed to *name* any module; whether that
module may be imported is decided separately, by resolving it to a file on disk
before the import happens.

`json:loads` is a harmless stand-in for the general case. A real attempt would
name something with a side effect at import time, and the same check refuses it
for the same reason.
