#!/bin/bash
set -euo pipefail

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/skills/macsentry"
if [[ $# -gt 1 ]]; then
    echo 'Usage: bash install.sh [codex|omp]' >&2
    exit 1
fi
case "${1:-omp}" in
    codex)
        skills_dir="${HOME}/.agents/skills"
        next_step='Start a Codex session and invoke $macsentry.'
        ;;
    omp)
        skills_dir="${HOME}/.omp/agent/skills"
        next_step='Start a new omp session and run /skill:macsentry.'
        ;;
    *)
        echo 'Usage: bash install.sh [codex|omp]' >&2
        exit 1
        ;;
esac
target="${skills_dir}/macsentry"

command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 1; }
if [[ -L "$target" && "$(readlink "$target")" == "$source_dir" ]]; then
    echo "Already installed: $target"
elif [[ -e "$target" || -L "$target" ]]; then
    echo "Refusing to replace existing skill: $target" >&2
    exit 1
else
    mkdir -p "$skills_dir"
    ln -s "$source_dir" "$target"
    echo "Installed: $target"
fi
printf '%s\n' "$next_step"
