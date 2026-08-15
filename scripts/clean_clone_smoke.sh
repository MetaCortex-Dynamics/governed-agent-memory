#!/usr/bin/env bash
set -uo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]]; then
  exit 2
fi

owner="$1"
repository="https://github.com/${owner}/governed-agent-memory.git"
temp_base="$(python3.12 -c 'import tempfile; print(tempfile.gettempdir())')" || exit 1
temp_root="$(mktemp -d)" || exit 1
if [[ -z "$temp_root" || "$temp_root" != "$temp_base"/* || ! -d "$temp_root" ]]; then
  exit 1
fi

cleanup() {
  if [[ -n "${temp_root:-}" && "$temp_root" == "$temp_base"/* && -d "$temp_root" ]]; then
    rm -rf -- "$temp_root"
  fi
}
trap cleanup EXIT

export GIT_TERMINAL_PROMPT=0
clone_dir="$temp_root/repository"
venv_dir="$temp_root/venv"
log_dir="$temp_root/logs"
mkdir -p "$log_dir" || exit 1
git clone --depth 1 "$repository" "$clone_dir" >"$log_dir/clone.out" 2>"$log_dir/clone.err" || exit 1
cd "$clone_dir" || exit 1

declare -A statuses
run_status() {
  local name="$1"
  shift
  "$@" >"$log_dir/${name}.out" 2>"$log_dir/${name}.err"
  statuses["$name"]=$?
}

branch="$(git branch --show-current)" || exit 1
[[ "$branch" == "main" ]] || exit 1
head_sha="$(git rev-parse HEAD)" || exit 1
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || exit 1
inventory_sha256="$(git ls-files | LC_ALL=C sort | sha256sum | cut -d' ' -f1)" || exit 1
[[ "$inventory_sha256" =~ ^[0-9a-f]{64}$ ]] || exit 1

python3.12 -m venv "$venv_dir" >"$log_dir/venv.out" 2>"$log_dir/venv.err" || exit 1
if [[ -f requirements.lock ]]; then
  run_status dependency_install "$venv_dir/bin/python" -m pip install --require-hashes --requirement requirements.lock
else
  run_status dependency_install "$venv_dir/bin/python" -m pip install --requirement requirements-dev.txt
fi
run_status compile "$venv_dir/bin/python" -m compileall -q src lambda scripts tests
run_status shell_syntax bash -n lambda/deploy.sh scripts/clean_clone_smoke.sh
if [[ -f requirements.lock ]]; then
  run_status inventory "$venv_dir/bin/python" scripts/verify_release.py
else
  run_status inventory "$venv_dir/bin/python" scripts/verify_release.py --initial-exact
fi
run_status boundary "$venv_dir/bin/python" scripts/check_boundary.py .
run_status secret_worktree "$venv_dir/bin/python" scripts/check_secrets.py --worktree
run_status secret_history "$venv_dir/bin/python" scripts/check_secrets.py --history
run_status license_boundary "$venv_dir/bin/python" scripts/check_license_boundary.py
run_status ruff_lint "$venv_dir/bin/ruff" check .
run_status ruff_format "$venv_dir/bin/ruff" format --check .
run_status mypy "$venv_dir/bin/mypy"
run_status pytest "$venv_dir/bin/pytest" -q
run_status bandit "$venv_dir/bin/bandit" -q -r src lambda scripts
if [[ -f requirements.lock ]]; then
  run_status dependency_audit "$venv_dir/bin/pip-audit" --requirement requirements.lock
else
  run_status dependency_audit "$venv_dir/bin/pip-audit" --requirement requirements-dev.txt
fi
run_status git_status git status --short

for name in bandit boundary compile dependency_audit dependency_install git_status inventory license_boundary mypy pytest ruff_format ruff_lint secret_history secret_worktree shell_syntax; do
  [[ "${statuses[$name]:-1}" -eq 0 ]] || exit 1
done
[[ ! -s "$log_dir/git_status.out" ]] || exit 1

report="{\"branch\":\"main\",\"command_statuses\":{\"bandit\":0,\"boundary\":0,\"compile\":0,\"dependency_audit\":0,\"dependency_install\":0,\"git_status\":0,\"inventory\":0,\"license_boundary\":0,\"mypy\":0,\"pytest\":0,\"ruff_format\":0,\"ruff_lint\":0,\"secret_history\":0,\"secret_worktree\":0,\"shell_syntax\":0},\"head_sha\":\"${head_sha}\",\"inventory_sha256\":\"${inventory_sha256}\",\"repository\":\"${repository}\",\"result\":\"ok\",\"schema_version\":1}"

cd "$temp_base" || exit 1
rm -rf -- "$temp_root" || exit 1
trap - EXIT
printf '%s\n' "$report"
