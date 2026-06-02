The Buzz — sol pbc org-activity visualization.

To run, serve this folder over http. The page is fully offline (no CDN,
no network), but Chrome blocks the three.js module imports over file://,
so double-clicking index.html shows a black screen. Serve it instead:

  cd buzz && python3 -m http.server 8000
  # then open http://localhost:8000 in your browser

Any static host works too. To share without running anything, use the
recorded MP4 instead.

All assets are local: three.js is vendored under vendor/, Comfortaa is under fonts/.
Loops every 30 seconds.
