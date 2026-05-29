#!/usr/bin/env bash
# run-local-setup.sh — Bootstrap local Fabric Docker network on EC2 (Stack 3).
# Run once on EC2 before the Stack 3 test sweep.
#
#   ssh -i scytale-ec2.pem ubuntu@<EC2_IP>
#   cd ~/microservice && bash shyware/sdk/web/adapters/ledger/fabric/deploy/run-local-setup.sh
#
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "${DIR}/setup.sh"
