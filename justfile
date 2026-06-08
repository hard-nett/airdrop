#!/bin/bash

docker_image := env_var_or_default('DOCKER_IMAGE', 'headstash-optimizer:0.17.0')
arch := `if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then echo "linux/arm64"; else echo "linux/amd64"; fi`

 
schema-codegen:
        @sh scripts/sh/schema-codegen.sh

# wasm:
#     docker run --rm \
#             -v "{{justfile_directory()}}/..":/workspace \
#             --mount type=volume,source=headstash_cache,target=/target \
#             --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
#             --platform {{arch}} \
#             {{docker_image}}


optimizer-build:
        docker build -t {{docker_image}} optimizer/

workspace-optimize: optimizer-build
        docker run --rm \
                -v "{{justfile_directory()}}/..":/workspace \
                --mount type=volume,source=headstash_cache,target=/target \
                --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
                --platform {{arch}} \
                {{docker_image}}

# Quick rebuild without rebuilding the Docker image
workspace-optimize-quick:
        docker run --rm \
                -v "{{justfile_directory()}}/..":/workspace \
                --mount type=volume,source=headstash_cache,target=/target \
                --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
                --platform {{arch}} \
                {{docker_image}}

# Clear build caches (useful after toolchain changes or if builds fail)
optimizer-clean:
        docker volume rm headstash_cache registry_cache 2>/dev/null || true%          