#!/bin/bash
set -e
echo "═══ TrueSendy VPS Deploy (n8n UNTOUCHED) ═══"

# 1. Verify n8n
echo "▸ n8n check..."
pm2 list 2>/dev/null | grep -iq n8n && echo "  n8n: ✓ (pm2)" || docker ps 2>/dev/null | grep -iq n8n && echo "  n8n: ✓ (docker)" || systemctl is-active n8n 2>/dev/null && echo "  n8n: ✓" || echo "  n8n: (verify manually)"

# 2. Clone + install
echo "▸ Installing TrueSendy..."
cd /opt
rm -rf truesendy 2>/dev/null
git clone --depth 1 https://github.com/0ngkur/truesendy.git truesendy
cd truesendy
npm install --production

# 3. .env
echo "▸ Configuring..."
JWT=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
cat > .env << EOF
JWT_SECRET=$JWT
MASTER_ADMIN_USERNAME=Shakil007
MASTER_ADMIN_PASSWORD=Shakil007Oldisgold100%
TRUST_PROXY=1
PORT=3000
ALLOW_DEV_PAYMENTS=true
EOF

# 4. pm2
echo "▸ Starting pm2..."
pm2 delete truesendy 2>/dev/null || true
pm2 start server.js --name truesendy
pm2 save 2>/dev/null

# 5. Test
sleep 3
curl -s http://localhost:3000/health && echo " ← TrueSendy ✓" || { echo "✗ FAILED — check: pm2 logs truesendy"; exit 1; }

# 6. Reverse proxy
echo "▸ Reverse proxy..."
if command -v nginx &>/dev/null; then
  cat > /etc/nginx/sites-available/truesendy.conf << 'NGX'
server {
    listen 80;
    server_name truesendy.com www.truesendy.com _;
    client_max_body_size 15M;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
NGX
  ln -sf /etc/nginx/sites-available/truesendy.conf /etc/nginx/sites-enabled/truesendy.conf
  nginx -t && nginx -s reload && echo "  ✓ Nginx (n8n untouched)"
  command -v certbot &>/dev/null && certbot --nginx -d truesendy.com --non-interactive --agree-tos -m admin@truesendy.com --redirect 2>/dev/null && echo "  ✓ HTTPS" || echo "  (certbot: configure manually or DNS not ready)"
elif command -v caddy &>/dev/null; then
  printf '\ntruesendy.com {\n  reverse_proxy 127.0.0.1:3000\n}\n' >> /etc/caddy/Caddyfile
  systemctl reload caddy && echo "  ✓ Caddy (auto-HTTPS, n8n untouched)"
else
  echo "  No proxy — access via http://72.60.195.145:3000"
fi

# 7. Final
echo ""
echo "▸ n8n still alive?"
pm2 list 2>/dev/null | grep -iq n8n && echo "  n8n: ✓ RUNNING (untouched)" || docker ps 2>/dev/null | grep -iq n8n && echo "  n8n: ✓ RUNNING (untouched)" || echo "  (verify n8n manually)"
echo ""
echo "═══ DONE ═══"
echo "TrueSendy: http://localhost:3000 (or truesendy.com when DNS → 72.60.195.145)"
echo "Admin: /masterenter (Shakil007 / Shakil007Oldisgold100%)"
echo "═════════"
