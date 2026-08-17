#!/usr/bin/env bash
set -euo pipefail

database_name='governed_agent_memory'
admin_url="${DATABASE_URL_SCHEMA_ADMIN-}"
[[ -n "$admin_url" ]] || exit 1

case "$admin_url" in
    postgres://* | postgresql://*) ;;
    *) exit 1 ;;
esac

base_url="${admin_url%%\?*}"
[[ "$base_url" != "$admin_url" ]] || exit 1
query="${admin_url#*\?}"
sslmode_count=0
IFS='&' read -r -a query_fields <<< "$query"
for field in "${query_fields[@]}"; do
    if [[ "$field" == 'sslmode=verify-full' ]]; then
        sslmode_count=$((sslmode_count + 1))
    elif [[ "$field" == sslmode=* ]]; then
        exit 1
    fi
done
[[ "$sslmode_count" -eq 1 ]] || exit 1

scheme="${base_url%%:*}"
authority_and_path="${base_url#*://}"
[[ "$authority_and_path" == */* ]] || exit 1
authority="${authority_and_path%%/*}"
[[ -n "$authority" ]] || exit 1

export COCKROACH_URL="${scheme}://${authority}/defaultdb?${query}"
unset DATABASE_URL_SCHEMA_ADMIN admin_url base_url query query_fields field

cockroach_bin="$(command -v cockroach 2>/dev/null)"
[[ -n "$cockroach_bin" ]] || exit 1
schema_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

collision_query="SELECT count(*) AS database_count FROM [SHOW DATABASES] WHERE database_name = '${database_name}'"
collision_output="$(
    "$cockroach_bin" sql --format=tsv --execute "$collision_query" 2>/dev/null
)"
collision_result="${collision_output##*$'\n'}"
[[ "$collision_result" == '0' ]] || exit 1
unset collision_output collision_result

"$cockroach_bin" sql \
    --execute "CREATE DATABASE ${database_name}" >/dev/null 2>&1
"$cockroach_bin" sql \
    --database "$database_name" \
    --file "$schema_dir/init.sql" >/dev/null 2>&1
"$cockroach_bin" sql \
    --database "$database_name" \
    --file "$schema_dir/roles.sql" >/dev/null 2>&1

printf '%s\n' 'crdb-deploy: ok'
