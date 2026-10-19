# shellcheck shell=bash
# Sourced by install.sh and ./opencloud after .env: picks the compose files and profiles for this install.
case "${OC_EDGE_MODE:-internal}" in
  internal) export COMPOSE_FILE=compose.yaml COMPOSE_PROFILES=edge,build ;;
  external) export COMPOSE_FILE=compose.yaml:compose.external.yaml; [ "${OC_BUILDER:-0}" = 1 ] && export COMPOSE_PROFILES=build || export COMPOSE_PROFILES= ;;
  *) echo "OC_EDGE_MODE must be internal or external"; exit 1 ;;
esac
# Optional generic model gateway (oc-llm-gateway).
[ "${OC_GENERIC_GATEWAY:-0}" = 1 ] && export COMPOSE_PROFILES="${COMPOSE_PROFILES:+$COMPOSE_PROFILES,}gateway"
# Observe mode: optional read-only file mounts, rendered by install.sh.
[ "${OC_OBSERVE:-0}" = 1 ] && [ -f "$OC_ROOT/observe.compose.yaml" ] && COMPOSE_FILE="$COMPOSE_FILE:$OC_ROOT/observe.compose.yaml"
# Host sources/mounts allowlisted in .env (rendered by install.sh).
[ -f "$OC_ROOT/host-mounts.compose.yaml" ] && COMPOSE_FILE="$COMPOSE_FILE:$OC_ROOT/host-mounts.compose.yaml"
# Builder AppArmor profile, where the kernel restricts unprivileged user namespaces and the profile is installed.
[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ] && [ -f /etc/apparmor.d/opencloud-builder ] && export OC_BUILDER_APPARMOR=opencloud-builder
true
