# ==============================================================================
# ESP32 HARDWARE SECURITY ATTACK MATRIX (POWERSHELL RUNNER)
# ==============================================================================

$script = Join-Path $PSScriptRoot "run_attack_matrix.py"
python $script
