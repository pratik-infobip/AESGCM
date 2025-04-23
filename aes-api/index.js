const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

app.post('/encrypt', (req, res) => {
  const { text, password } = req.body;
  if (!text || !password) {
    return res.status(400).json({ error: 'Missing text or password' });
  }

  try {
    const hash = crypto.createHash('sha1').update(password).digest();
    const key = hash.slice(0, 16); // AES-128 key
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    const result = Buffer.concat([iv, encrypted, tag]).toString('base64');

    res.json({ encrypted: result });
  } catch (e) {
    res.status(500).json({ error: 'Encryption failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AES API running on port ${PORT}`);
});
