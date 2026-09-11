# Файлик для настроек системы корреляции
WINDOW_SIZE = 600.0
DEPTH=20

BASE_WEIGHTS = {
    "manager_reads_manifest" : 1.0,
    "manager_creates_lifecycle_shell_child" : 1.0,
    "manager_creates_lifecycle_shell" : 2.0,
    "shell_starts_runtime_child" : 1.0,
    "shell_starts_runtime" : 2.5,
    "runtime_reads_install_script" : 4.0,
}

PERIODICITY = {
    "manager_reads_manifest" : 0.0,
    "manager_creates_lifecycle_shell_child" : 30.0,
    "manager_creates_lifecycle_shell" : 30.0,
    "shell_starts_runtime_child" : 30.0,
    "shell_starts_runtime" : 30.0,
    "runtime_reads_install_script" : 60.0,
}
