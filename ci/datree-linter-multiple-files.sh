#!/bin/bash

path="${1:-.}"
final_exit_code=0

while read -r kustomization; do
    dir="$(dirname "$kustomization")"
    echo "Datree Kustomization Test: $kustomization"
    set +e
    datree kustomize test "$dir"
    exitcode=$?
    set -e
    if [ "$exitcode" -gt "$final_exit_code" ]; then
        final_exit_code="$exitcode"
    fi
done < <(find "$path" -type f -name 'kustomization.y*ml')

if [ "$final_exit_code" = 0 ]; then
    echo "Success"
else
    echo "Violations found, returning exit code $final_exit_code"
fi
exit "$final_exit_code"