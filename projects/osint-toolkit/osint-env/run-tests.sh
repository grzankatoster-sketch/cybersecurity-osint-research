#!/bin/sh
# Uruchamia pytest kazdego z 7 projektow (etap "tests" obrazu).
rc=0
for p in username-engine dns-audit hibp-monitor exif-map phone-check net-intel site-audit; do
  echo "=== $p"
  (cd "/tests/$p" && python -m pytest -q -p no:cacheprovider) || rc=1
done
exit $rc
