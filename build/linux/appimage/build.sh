#!/usr/bin/env bash
# Copyright (c) 2018-Present Lea Anthony
# SPDX-License-Identifier: MIT

# Fail script on any error
set -euxo pipefail

# Define variables
APP_DIR="${APP_NAME}.AppDir"

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
    ./linuxdeploy-x86_64.AppImage --appdir "${APP_DIR}" --output appimage
else
    # Download linuxdeploy and make it executable (arm64)
    wget -q -4 -N https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-aarch64.AppImage
    chmod +x linuxdeploy-aarch64.AppImage

    # Run linuxdeploy to bundle the application (arm64)
    ./linuxdeploy-aarch64.AppImage --appdir "${APP_DIR}" --output appimage
fi

# Expand the generated filename (the old quoted glob was a literal '*').
# The desktop Name may capitalise the product differently from APP_NAME.
shopt -s nullglob nocaseglob
images=( "${APP_NAME}"*.AppImage )
# A previous build may already have the final filename. Prefer a newly
# generated architecture-qualified file and replace the previous output.
if [ "${#images[@]}" -gt 1 ]; then
    generated=()
    for candidate in "${images[@]}"; do
        if [ "$candidate" != "${APP_NAME}.AppImage" ]; then
            generated+=( "$candidate" )
        fi
    done
    images=( "${generated[@]}" )
fi
if [ "${#images[@]}" -ne 1 ]; then
    echo "Expected one generated ${APP_NAME} AppImage, found ${#images[@]}" >&2
    exit 1
fi
if [ "${images[0]}" != "${APP_NAME}.AppImage" ]; then
    mv -- "${images[0]}" "${APP_NAME}.AppImage"
fi
