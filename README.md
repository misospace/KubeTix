# KubeTix 🎫

> Temporary Kubernetes access, on demand

Share secure, time-limited Kubernetes access with your team. No more permanent admin credentials or messy kubeconfig sharing.

## 🚀 Features

- **Temporary Access** - Generate kubeconfig access with automatic expiry (1h, 4h, 24h, or custom)
- **Encrypted Storage** - Kubeconfigs are encrypted at rest with Fernet (AES)
- **Audit Logging** - Track who accessed what and when
- **Instant Revocation** - Cut off access immediately, anytime
- **Simple CLI** - Easy to use command-line interface
- **Namespace & Role Control** - Fine-grained access control

## 💡 Use Cases

- **On-call engineers** - Grant temporary cluster access during incidents
- **Contractors** - Give time-limited access without permanent credentials
- **Team collaboration** - Share cluster access securely without password managers
- **Security compliance** - Meet "least privilege" and "time-bound access" requirements

## 📦 Installation

```bash
# Clone and install
git clone https://github.com/joryirving/KubeTix.git
cd KubeTix
pip install -r requirements.txt
```

## 🎯 Quick Start

### Create a temporary grant

```bash
# Create 4-hour access to prod cluster
python kc-share.py create --cluster prod --role edit --expiry 4

# Create 1-hour access to specific namespace
python kc-share.py create --cluster staging -n default --role view --expiry 1
```

### Share access

```bash
# List active grants
python kc-share.py list

# Download temporary context
python kc-share.py download <grant-id>
```

### Manage access

```bash
# Revoke access immediately
python kc-share.py revoke <grant-id>
```

## 🔒 Security

- **Encryption**: Kubeconfigs encrypted with Fernet (AES-128-CBC)
- **Expiry**: Automatic expiration enforced server-side
- **Audit**: Complete audit trail of all access
- **Revocation**: Instant access revocation
- **No plaintext**: Kubeconfigs never stored in plain text

## 🧪 Testing

```bash
# Run all tests
./run_tests.sh

# Run unit tests only
python3 test_kc_share.py -v

# Run integration tests only
python3 test_integration.py -v
```

## 🐳 Docker

### Build and Run

```bash
# Build the image
docker build -t kubetix .

# Run with your kubeconfig
docker run -v ~/.kube:/root/.kube:ro -v kubetix_data:/root/.kc-share kubetix list
```

### Docker Compose

```bash
docker-compose up -d
```

## 🌐 Web UI

The web dashboard is in the `kubetix-web/` directory:

```bash
cd kubetix-web
npm install
npm run dev
```

Visit http://localhost:3000 to access the dashboard.

## 📚 Documentation

- [SPEC.md](SPEC.md) - Project specification
- [TEST_PLAN.md](TEST_PLAN.md) - Test coverage and plan

## 🛣️ Roadmap

- [x] Web UI dashboard (in `kubetix-web/`)
- [x] Backend API (in `kubetix-api/`)
- [x] Team features (multiple users, SSO)
- [ ] Cloud provider integrations (EKS/GKE/AKS)
- [ ] Slack/Teams bot integration
- [x] Docker container support
- [x] API endpoints for automation

## 🤝 Contributing

Contributions welcome! Feel free to open issues or submit PRs.

## 📄 License

MIT License - See LICENSE file for details

---

**Made with ❤️ by [Jory Irving](https://github.com/joryirving)**
