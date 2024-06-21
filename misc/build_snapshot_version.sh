#!/bin/bash

set -e
trap "exit" INT

readonly project_path=$(dirname "$(dirname "$(realpath "$0")")")
cd "$project_path"
export GORELEASER_CURRENT_TAG=$(git tag -l --sort=-creatordate | head -n 1)
goreleaser build --snapshot --clean --single-target -f "$project_path"/.goreleaser.yaml
