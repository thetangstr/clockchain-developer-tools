#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  git \
  jq \
  unzip

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y --no-install-recommends \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install
mv /usr/local/bin/aws /usr/local/bin/aws-real
cat >/usr/local/bin/aws <<'AWS_WRAPPER'
#!/usr/bin/env bash
set -uo pipefail

real_aws=/usr/local/bin/aws-real
if ! tmp_home=$(mktemp -d "${TMPDIR:-/tmp}/aws-home.XXXXXX"); then
  exit 1
fi
cleanup_status=0

cleanup() {
  rm -rf "$tmp_home" || cleanup_status=$?
}

trap cleanup EXIT

HOME=$tmp_home "$real_aws" "$@"
aws_status=$?
cleanup
trap - EXIT

if (( cleanup_status != 0 )); then
  exit "$cleanup_status"
fi

exit "$aws_status"
AWS_WRAPPER
chmod 0755 /usr/local/bin/aws
test ! -e /home/ubuntu/.aws
sudo -H -u ubuntu aws --region us-west-2 ssm get-parameter --name /clockchain/mcp/PING >/dev/null
test ! -e /home/ubuntu/.aws

usermod -aG docker ubuntu
systemctl enable --now docker
