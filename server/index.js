[21:51, 09/03/2026] A.B: cd "$env:USERPROFILE\Desktop\viewplay-render"; notepad .\server\index.js
[21:52, 09/03/2026] A.B: app.get("/me", auth, (req, res) => {
  ...
});

// ✅ COLLE ICI
app.get("/watched", auth, (req, res) => {
  const userId = req.userId;

  const rows = db.prepare(
    `SELECT DISTINCT video_id as videoId
     FROM events
     WHERE user_id = ?
       AND type = 'video_completed'
       AND video_id IS NOT NULL`
  ).all(userId);

  res.json({ items: rows.map(r => String(r.videoId)) });
});

app.post("/events", auth, (req, res) => {
  ...
});

...

app.listen(PORT, () => {
  ...
});