const express = require('express');
const app = express();
app.get('/api/_diag/raw-id-fresh', (req, res) => {
  res.json({ raw_id: 'FRESH_BUILD_' + Date.now(), port: process.env.PORT || 10000 });
});
const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`FRESH_API listening on ${port}`));
