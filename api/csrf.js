import crypto from 'crypto';

export default async function handler(req, res) {
  const token = crypto.randomBytes(16).toString('hex');
  res.setHeader(
    'Set-Cookie',
    `csrf_token=${token}; HttpOnly; Secure; SameSite=Strict; Path=/`
  );
  res.json({ success: true }); 
}
