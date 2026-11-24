#!/bin/sh
# Builds agent-secrets and installs the `op` wrapper.
# Keychain trusts the exact binary, so after a rebuild, store each token again.
set -e
cd "$(dirname "$0")"
mkdir -p bin
swiftc -O main.swift -o bin/agent-secrets
codesign --force --sign - --options runtime bin/agent-secrets
ln -sf "$PWD/bin/agent-secrets" ~/.local/bin/agent-secrets
cat > ~/.local/bin/op <<EOF
#!/bin/sh
exec "$PWD/bin/agent-secrets" op "\$@"
EOF
chmod +x ~/.local/bin/op
echo "Built and installed."
