#!/usr/bin/env bash
# Copyright (c) 2018-Present Lea Anthony
# SPDX-License-Identifier: MIT

# Fail script on any error
set -euxo pipefail

# Define variables
build_dir=$(pwd -P)
APP_DIR="${build_dir}/${APP_NAME}.AppDir"
# Only accept output from this invocation. Preserve the previous final artifact
# if packaging fails, but never report that artifact as a successful new build.
output_dir=$(mktemp -d "${build_dir}/.wireguide-appimage.XXXXXX")
trap 'rm -rf -- "$output_dir"' EXIT

# Create AppDir structure
mkdir -p "${APP_DIR}/usr/bin"
cp -r "${APP_BINARY}" "${APP_DIR}/usr/bin/"
cp "${ICON_PATH}" "${APP_DIR}/"
cp "${DESKTOP_FILE}" "${APP_DIR}/"

if [[ $(uname -m) == *x86_64* ]]; then
    # Download linuxdeploy and make it executable
    wget -q -4 -N https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
    chmod +x linuxdeploy-x86_64.AppImage

    # Run linuxdeploy to bundle the application
    (cd "$output_dir" && "${build_dir}/linuxdeploy-x86_64.AppImage" --appdir "${APP_DIR}" --output appimage)
else
    # Download linuxdeploy and make it executable (arm64)
    wget -q -4 -N https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-aarch64.AppImage
    chmod +x linuxdeploy-aarch64.AppImage

    # Run linuxdeploy to bundle the application (arm64)
    (cd "$output_dir" && "${build_dir}/linuxdeploy-aarch64.AppImage" --appdir "${APP_DIR}" --output appimage)
fi

# Expand the generated filename (the old quoted glob was a literal '*').
# The desktop Name may capitalise the product differently from APP_NAME.
shopt -s nullglob nocaseglob
images=( "${output_dir}/${APP_NAME}"*.AppImage )
if [ "${#images[@]}" -ne 1 ]; then
    echo "Expected one generated ${APP_NAME} AppImage, found ${#images[@]}" >&2
    exit 1
fi
mv -- "${images[0]}" "${build_dir}/${APP_NAME}.AppImage"
