#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import glob
import json
import os
import pathlib
import shutil
import subprocess
import sys


def run(command):
    result = subprocess.run(command, capture_output=True, text=True)
    return {
        "available": True,
        "exit_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def maybe_run(command):
    executable = command[0]
    if shutil.which(executable) is None:
        return {
            "available": False,
            "exit_code": None,
            "stdout": "",
            "stderr": f"{executable} not found",
        }
    return run(command)


def read_os_pretty_name():
    os_release = pathlib.Path("/etc/os-release")
    if not os_release.exists():
        return None

    for line in os_release.read_text().splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def split_lines(text):
    return [line for line in text.splitlines() if line.strip()]


lspci = maybe_run(
    ["bash", "-lc", "lspci -nn | egrep -i 'vga|3d|display|nvidia' || true"]
)
lsmod = maybe_run(["bash", "-lc", "lsmod | egrep 'nvidia|nouveau' || true"])
ubuntu_drivers = maybe_run(["bash", "-lc", "ubuntu-drivers devices 2>/dev/null || true"])
nvidia_smi = maybe_run(["nvidia-smi", "-L"])
nvcc = maybe_run(["nvcc", "--version"])

all_pci_devices = split_lines(lspci["stdout"])
gpu_pci_devices = [
    line
    for line in all_pci_devices
    if "NVIDIA" in line
    and (
        "VGA compatible controller" in line
        or "3D controller" in line
        or "Display controller" in line
    )
]
loaded_modules = split_lines(lsmod["stdout"])
recommended_drivers = []
for line in split_lines(ubuntu_drivers["stdout"]):
    if line.startswith("driver   :"):
        recommended_drivers.append(line.split(":", 1)[1].strip())

device_nodes = sorted(glob.glob("/dev/nvidia*"))
nouveau_loaded = any(line.startswith("nouveau ") for line in loaded_modules)
nvidia_module_loaded = any(line.startswith("nvidia ") for line in loaded_modules)
nvidia_smi_ok = nvidia_smi["available"] and nvidia_smi["exit_code"] == 0
nvcc_ok = nvcc["available"] and nvcc["exit_code"] == 0

blockers = []
if not gpu_pci_devices:
    blockers.append("no NVIDIA GPU was detected via lspci")
if nouveau_loaded:
    blockers.append("nouveau kernel module is loaded")
if not nvidia_module_loaded:
    blockers.append("proprietary nvidia kernel module is not loaded")
if not device_nodes:
    blockers.append("no /dev/nvidia* device nodes are present")
if not nvidia_smi_ok:
    blockers.append("nvidia-smi is unavailable or failing")
if not nvcc_ok:
    blockers.append("nvcc is unavailable or failing")

payload = {
    "hostname": os.uname().nodename,
    "kernel": os.uname().release,
    "os_pretty_name": read_os_pretty_name(),
    "display_devices": all_pci_devices,
    "gpu_pci_devices": gpu_pci_devices,
    "loaded_modules": loaded_modules,
    "recommended_drivers": recommended_drivers,
    "device_nodes": device_nodes,
    "nouveau_loaded": nouveau_loaded,
    "nvidia_module_loaded": nvidia_module_loaded,
    "nvidia_smi": {
        "available": nvidia_smi["available"],
        "exit_code": nvidia_smi["exit_code"],
        "stdout": nvidia_smi["stdout"],
        "stderr": nvidia_smi["stderr"],
    },
    "nvcc": {
        "available": nvcc["available"],
        "exit_code": nvcc["exit_code"],
        "stdout": nvcc["stdout"],
        "stderr": nvcc["stderr"],
    },
    "cuda_ready": not blockers,
    "blockers": blockers,
}

print(json.dumps(payload))
sys.exit(0 if payload["cuda_ready"] else 1)
PY
