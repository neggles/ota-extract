#!/usr/bin/env bash
set -e

# get the parent directory of the script
SCRIPT_DIR=$(
    cd -- "$(dirname "$0")" &>/dev/null
    pwd -P
)

# change to one level up from script
pushd "${SCRIPT_DIR}/.." >/dev/null

# retrieve the latest proto files
curl -L 'https://android.googlesource.com/platform/system/update_engine/+/refs/heads/master/update_metadata.proto?format=TEXT' | base64 -d >assets/update_metadata.proto
curl -L 'https://android.googlesource.com/platform/external/puffin/+/HEAD/src/puffin.proto?format=TEXT' | base64 -d >assets/puffin.proto

# compile python module
if (command -v protoc-gen-mypy); then
    protoc --proto_path=assets --python_out=src/update_metadata --mypy_out=src/update_metadata assets/update_metadata.proto assets/puffin.proto
else
    echo "Warning: protoc-gen-mypy not found. Skipping protobuf pyi generation, you may need to clean up src/update_metadata/*.pyi"
    protoc --proto_path=assets --python_out=src/update_metadata assets/update_metadata.proto assets/puffin.proto
fi

# return to previous directory
popd >/dev/null

# done
exit 0
