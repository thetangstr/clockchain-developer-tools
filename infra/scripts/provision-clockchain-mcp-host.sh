#!/usr/bin/env bash
set -euo pipefail

ACCOUNT_ID="570035913370"
REGION="us-west-2"
NAME="clockchain-mcp"
KEY_NAME="clockchain-mcp"
KEY_PATH="/Users/Kailor/.ssh/clockchain-mcp.pem"
ROLE_NAME="clockchain-mcp-ec2-role"
PROFILE_NAME="clockchain-mcp-instance-profile"
POLICY_NAME="clockchain-mcp-ssm-parameter-read"
SG_NAME="clockchain-mcp-sg"
PARAM_NAME="/clockchain/mcp/PING"
AMI_PARAM="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
USER_DATA_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/clockchain-mcp-user-data.sh"

INSTANCE_TAG_SPEC="ResourceType=instance,Tags=[{Key=Name,Value=${NAME}},{Key=Project,Value=clockchain},{Key=Component,Value=mcp},{Key=ManagedBy,Value=codex-b2}]"
VOLUME_TAG_SPEC="ResourceType=volume,Tags=[{Key=Name,Value=${NAME}-root},{Key=Project,Value=clockchain},{Key=Component,Value=mcp},{Key=ManagedBy,Value=codex-b2}]"

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

aws_region() {
  aws --region "$REGION" "$@"
}

exists_key_pair() {
  aws_region ec2 describe-key-pairs --key-names "$KEY_NAME" >/dev/null 2>&1
}

exists_iam_role() {
  aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1
}

exists_instance_profile() {
  aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1
}

existing_sg_ids() {
  aws_region ec2 describe-security-groups \
    --filters "Name=group-name,Values=${SG_NAME}" \
    --query 'SecurityGroups[].GroupId' \
    --output text
}

existing_instance_ids() {
  aws_region ec2 describe-instances \
    --filters "Name=tag:Name,Values=${NAME}" "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text
}

existing_eip_allocations() {
  aws_region ec2 describe-addresses \
    --filters "Name=tag:Name,Values=${NAME}" \
    --query 'Addresses[].AllocationId' \
    --output text
}

exists_parameter() {
  aws_region ssm get-parameter --name "$PARAM_NAME" >/dev/null 2>&1
}

validate_clean_slate() {
  [[ ! -e "$KEY_PATH" ]] || die "private key path already exists: ${KEY_PATH}"
  ! exists_key_pair || die "EC2 key pair already exists: ${KEY_NAME}"
  ! exists_iam_role || die "IAM role already exists: ${ROLE_NAME}"
  ! exists_instance_profile || die "IAM instance profile already exists: ${PROFILE_NAME}"
  [[ -z "$(existing_sg_ids)" ]] || die "security group already exists: ${SG_NAME}"
  [[ -z "$(existing_instance_ids)" ]] || die "instance already exists with Name=${NAME}"
  [[ -z "$(existing_eip_allocations)" ]] || die "Elastic IP already exists with Name=${NAME}"
  ! exists_parameter || die "SSM parameter already exists: ${PARAM_NAME}"
}

validate_identity() {
  local actual_account
  actual_account="$(aws sts get-caller-identity --query Account --output text)"
  [[ "$actual_account" == "$ACCOUNT_ID" ]] || die "wrong AWS account: expected ${ACCOUNT_ID}, got ${actual_account}"

  local configured_region
  configured_region="$(aws configure get region || true)"
  if [[ -n "$configured_region" && "$configured_region" != "$REGION" ]]; then
    die "configured AWS region is ${configured_region}; this script is locked to ${REGION}"
  fi
}

select_public_default_subnet() {
  local vpc_id
  vpc_id="$(aws_region ec2 describe-vpcs \
    --filters Name=is-default,Values=true \
    --query 'Vpcs[0].VpcId' \
    --output text)"
  [[ -n "$vpc_id" && "$vpc_id" != "None" ]] || die "no default VPC found in ${REGION}"

  while read -r subnet_id; do
    [[ -n "$subnet_id" ]] || continue
    local route_count
    route_count="$(aws_region ec2 describe-route-tables \
      --filters "Name=association.subnet-id,Values=${subnet_id}" \
      --query "length(RouteTables[].Routes[?DestinationCidrBlock=='0.0.0.0/0' && starts_with(GatewayId, 'igw-')])" \
      --output text)"
    if [[ "$route_count" == "0" ]]; then
      route_count="$(aws_region ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=${vpc_id}" Name=association.main,Values=true \
        --query "length(RouteTables[].Routes[?DestinationCidrBlock=='0.0.0.0/0' && starts_with(GatewayId, 'igw-')])" \
        --output text)"
    fi
    if [[ "$route_count" != "0" ]]; then
      printf '%s\t%s\n' "$vpc_id" "$subnet_id"
      return 0
    fi
  done < <(aws_region ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${vpc_id}" Name=default-for-az,Values=true Name=map-public-ip-on-launch,Values=true \
    --query 'Subnets[].SubnetId' \
    --output text | tr '\t' '\n')

  die "no default subnet has public-IP mapping and a 0.0.0.0/0 route to an internet gateway"
}

current_public_cidr() {
  local ip
  ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "could not determine executor public IPv4 address"
  printf '%s/32\n' "$ip"
}

create_instance_role() {
  local assume_doc policy_doc
  assume_doc="$(mktemp)"
  policy_doc="$(mktemp)"

  cat > "$assume_doc" <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON

  cat > "$policy_doc" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:${REGION}:${ACCOUNT_ID}:parameter/clockchain/mcp/*"
    }
  ]
}
JSON

  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://${assume_doc}" \
    --tags Key=Name,Value="$NAME" Key=Project,Value=clockchain Key=Component,Value=mcp Key=ManagedBy,Value=codex-b2 >/dev/null
  aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$POLICY_NAME" \
    --policy-document "file://${policy_doc}"
  aws iam create-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --tags Key=Name,Value="$NAME" Key=Project,Value=clockchain Key=Component,Value=mcp Key=ManagedBy,Value=codex-b2 >/dev/null
  aws iam add-role-to-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --role-name "$ROLE_NAME"

  rm -f "$assume_doc" "$policy_doc"
}

create_security_group() {
  local vpc_id="$1" ssh_cidr="$2" sg_id
  sg_id="$(aws_region ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "Clockchain MCP host ingress" \
    --vpc-id "$vpc_id" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=${SG_NAME}},{Key=Project,Value=clockchain},{Key=Component,Value=mcp},{Key=ManagedBy,Value=codex-b2}]" \
    --query GroupId \
    --output text)"

  aws_region ec2 authorize-security-group-ingress \
    --group-id "$sg_id" \
    --ip-permissions \
      "IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0,Description=public-http}]" \
      "IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=public-https}]" \
      "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=${ssh_cidr},Description=executor-ssh}]" >/dev/null

  printf '%s\n' "$sg_id"
}

create_key_pair() {
  umask 077
  mkdir -p "$(dirname "$KEY_PATH")"
  aws_region ec2 create-key-pair \
    --key-name "$KEY_NAME" \
    --key-type ed25519 \
    --key-format pem \
    --tag-specifications "ResourceType=key-pair,Tags=[{Key=Name,Value=${KEY_NAME}},{Key=Project,Value=clockchain},{Key=Component,Value=mcp},{Key=ManagedBy,Value=codex-b2}]" \
    --query KeyMaterial \
    --output text > "$KEY_PATH"
  chmod 600 "$KEY_PATH"
}

run_instance() {
  local subnet_id="$1" sg_id="$2" ami_id="$3" instance_id
  instance_id="$(aws_region ec2 run-instances \
    --image-id "$ami_id" \
    --instance-type t3.small \
    --key-name "$KEY_NAME" \
    --iam-instance-profile "Name=${PROFILE_NAME}" \
    --network-interfaces "DeviceIndex=0,SubnetId=${subnet_id},Groups=[${sg_id}],AssociatePublicIpAddress=true" \
    --metadata-options HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=2 \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":20,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":true}}]' \
    --credit-specification CpuCredits=standard \
    --user-data "file://${USER_DATA_PATH}" \
    --tag-specifications "$INSTANCE_TAG_SPEC" "$VOLUME_TAG_SPEC" \
    --query 'Instances[0].InstanceId' \
    --output text)"
  printf '%s\n' "$instance_id"
}

allocate_and_associate_eip() {
  local instance_id="$1" allocation_id public_ip
  allocation_id="$(aws_region ec2 allocate-address \
    --domain vpc \
    --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=${NAME}},{Key=Project,Value=clockchain},{Key=Component,Value=mcp},{Key=ManagedBy,Value=codex-b2}]" \
    --query AllocationId \
    --output text)"
  aws_region ec2 associate-address --instance-id "$instance_id" --allocation-id "$allocation_id" >/dev/null
  public_ip="$(aws_region ec2 describe-addresses --allocation-ids "$allocation_id" --query 'Addresses[0].PublicIp' --output text)"
  printf '%s\t%s\n' "$allocation_id" "$public_ip"
}

main() {
  require_cmd aws
  require_cmd curl
  require_cmd jq
  [[ -f "$USER_DATA_PATH" ]] || die "missing user-data file: ${USER_DATA_PATH}"

  validate_identity
  validate_clean_slate

  local vpc_id subnet_id ssh_cidr ami_id sg_id instance_id allocation_id public_ip
  read -r vpc_id subnet_id < <(select_public_default_subnet)
  ssh_cidr="$(current_public_cidr)"
  ami_id="$(aws_region ssm get-parameter --name "$AMI_PARAM" --query 'Parameter.Value' --output text)"
  [[ "$ami_id" == ami-* ]] || die "Canonical SSM AMI parameter returned unexpected value: ${ami_id}"

  log "Provisioning ${NAME} in ${ACCOUNT_ID}/${REGION} using ${ami_id}; SSH ingress ${ssh_cidr}"

  create_key_pair
  create_instance_role
  log "Waiting for IAM instance profile propagation"
  sleep 20
  sg_id="$(create_security_group "$vpc_id" "$ssh_cidr")"
  aws_region ssm put-parameter \
    --name "$PARAM_NAME" \
    --type SecureString \
    --value "clockchain-mcp-ping" \
    --description "Nonsecret provisioning test parameter for ${NAME}" >/dev/null
  instance_id="$(run_instance "$subnet_id" "$sg_id" "$ami_id")"
  log "Waiting for instance ${instance_id} to enter running state before EIP association"
  aws_region ec2 wait instance-running --instance-ids "$instance_id"
  read -r allocation_id public_ip < <(allocate_and_associate_eip "$instance_id")

  log "Waiting for instance ${instance_id} to pass status checks"
  aws_region ec2 wait instance-status-ok --instance-ids "$instance_id"

  printf 'INSTANCE_ID=%s\n' "$instance_id"
  printf 'ALLOCATION_ID=%s\n' "$allocation_id"
  printf 'SECURITY_GROUP_ID=%s\n' "$sg_id"
  printf 'PUBLIC_IP=%s\n' "$public_ip"
  printf 'SSH_CIDR=%s\n' "$ssh_cidr"
  printf 'AMI_ID=%s\n' "$ami_id"
  printf 'SUBNET_ID=%s\n' "$subnet_id"
  printf 'VPC_ID=%s\n' "$vpc_id"
  printf 'IAM_ROLE=%s\n' "$ROLE_NAME"
  printf 'INSTANCE_PROFILE=%s\n' "$PROFILE_NAME"
  printf 'SSM_PARAMETER=%s\n' "$PARAM_NAME"
}

main "$@"
