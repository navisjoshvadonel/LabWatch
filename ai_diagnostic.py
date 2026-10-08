"""
ai_diagnostic.py
College Lab PC Fault Reporting System (LabPulse)
AI & Data Science (AIDS) Department Smart Diagnostic Assistant ("AI Lab Doctor")

Provides domain-specific automated root cause analysis (RCA), student instant
self-help guidance, and technician auto-remediation playbook recommendations
for AI/ML, Data Science, and networking failure modes.
"""

import re
from typing import Any, Dict


class AIDSLabDiagnosticEngine:
    """
    Heuristic & Pattern-Matching Diagnostic Engine specifically trained on
    workloads, tools, and infrastructure in an AI & Data Science engineering lab
    (PyTorch, TensorFlow, CUDA, JupyterLab, Ollama, HuggingFace, Conda, Linux/Windows).
    """

    PATTERNS = [
        {
            "id": "cuda_vram_oom",
            "name": "CUDA GPU Out-Of-Memory (OOM) / VRAM Allocation Lock",
            "regex": r"(cuda|out of memory|oom|vram|torch\.cuda|cuda error|allocat.*memory|device-side assert|cudnn|gpu memory|killed.*python)",
            "category": "Software Crash",
            "severity": "High",
            "root_cause": (
                "Workstation NVIDIA GPU VRAM was exhausted by a PyTorch/TensorFlow training session "
                "allocating large batch sizes or holding uncollected computational graph tensors."
            ),
            "student_advice": (
                "1. Add `import gc; gc.collect(); torch.cuda.empty_cache()` before your training loop.\n"
                "2. Decrease your batch size (e.g., from 64 to 16 or 8).\n"
                "3. In Jupyter, click 'Kernel' -> 'Restart Kernel & Clear All Outputs'."
            ),
            "recommended_playbook": "kill_ai_zombies",
            "playbook_title": "Terminate AI Zombie Workers & Flush VRAM",
            "est_resolution_time": "10 - 15 seconds",
            "auto_remediable": True,
            "confidence": 0.96
        },
        {
            "id": "jupyter_kernel_crash",
            "name": "JupyterLab Kernel Panic / Defunct Process",
            "regex": r"(kernel died|kernel disconnected|kernel busy|kernel error|jupyter.*freeze|notebook.*stuck|cell not running|infinite loop|interrupted)",
            "category": "Software Crash",
            "severity": "Medium",
            "root_cause": (
                "The IPython/JupyterLab kernel encountered a fatal segmentation fault in a C-extension "
                "(OpenCV, NumPy, Cython) or is trapped in a non-terminating CPU loop blocking socket communication."
            ),
            "student_advice": (
                "1. Check the bottom status bar in JupyterLab for 'Kernel: Busy' or 'Disconnected'.\n"
                "2. Click the square 'Interrupt Kernel' button in the toolbar.\n"
                "3. If unresponsive, use 'Kernel' -> 'Restart Kernel'."
            ),
            "recommended_playbook": "service_restart",
            "playbook_title": "Restart JupyterLab & Python Daemons",
            "est_resolution_time": "12 seconds",
            "auto_remediable": True,
            "confidence": 0.94
        },
        {
            "id": "network_proxy_hf_timeout",
            "name": "Institutional Gateway / Proxy Timeout on Model Download",
            "regex": r"(pip.*install|huggingface|read timeout|connection broken|proxy|ssl.*error|certificate|model weights|kaggle.*download|download.*fail|curl.*fail)",
            "category": "Network Connectivity",
            "severity": "Medium",
            "root_cause": (
                "Network traffic chokepoint or proxy misconfiguration communicating through "
                "Mepco Schlenk Departmental Gateway (192.16.16.200) during large weight downloads."
            ),
            "student_advice": (
                "1. Verify campus proxy settings in terminal: `export http_proxy=http://192.16.16.200:3128`\n"
                "2. For HuggingFace, utilize pre-downloaded model checkpoints stored on the AIDS local NAS drive (`/mnt/aids_models`).\n"
                "3. Use `pip install --timeout=60 <package>`."
            ),
            "recommended_playbook": "network_self_heal",
            "playbook_title": "Network Stack Reset & Gateway Latency Sweep",
            "est_resolution_time": "8 seconds",
            "auto_remediable": True,
            "confidence": 0.92
        },
        {
            "id": "scratch_disk_exhaustion",
            "name": "Workstation SSD / Scratch Space Exhaustion",
            "regex": r"(no space left|disk full|database or disk is full|tmp full|write error|checkpoint failed|enospc|permission denied.*cache)",
            "category": "Hardware Fault",
            "severity": "High",
            "root_cause": (
                "Workstation local SSD scratch partition (`C:\\Users` or `/home`) reached 100% capacity "
                "due to accumulated HuggingFace Hub transformers cache, pip wheels, or uncompressed datasets."
            ),
            "student_advice": (
                "1. Clear your personal model cache in terminal: `rm -rf ~/.cache/huggingface/hub` or delete `%TEMP%`.\n"
                "2. Move datasets to the secondary D: drive data partition.\n"
                "3. Check available drive capacity using `df -h` or File Explorer."
            ),
            "recommended_playbook": "disk_scratch_purge",
            "playbook_title": "Purge Scratch Temp & HuggingFace Locks",
            "est_resolution_time": "15 seconds",
            "auto_remediable": True,
            "confidence": 0.95
        },
        {
            "id": "os_hard_freeze",
            "name": "Operating System Hard Freeze / Display Server Lock",
            "regex": r"(frozen|black screen|blue screen|not responding|system lockup|mouse stuck|reboot|pc hung|crash.*hard|power cut)",
            "category": "Operating System",
            "severity": "Critical",
            "root_cause": (
                "Complete kernel-level lockup or graphics compositor deadlock under sustained 100% CPU/GPU multi-threading, "
                "rendering input peripherals and SSH unresponsive."
            ),
            "student_advice": (
                "1. Check if the NumLock or CapsLock LED on your keyboard responds to keypresses.\n"
                "2. If hardware LEDs are unresponsive, the system is fully locked.\n"
                "3. Lab Technicians can trigger a dual-broadcast Wake-on-LAN Remote Restart instantly."
            ),
            "recommended_playbook": "wol_restart",
            "playbook_title": "Dual-Broadcast WoL Remote Hard Restart",
            "est_resolution_time": "30 - 45 seconds",
            "auto_remediable": True,
            "confidence": 0.93
        },
        {
            "id": "network_physical_unreachable",
            "name": "Physical Ethernet Disconnection / ARP Desynchronization",
            "regex": r"(destination host unreachable|network down|ping timeout|offline|ethernet unplugged|ip conflict|no internet|cable loose)",
            "category": "Network Connectivity",
            "severity": "Critical",
            "root_cause": (
                "Layer 1/2 network disruption: RJ-45 patch cable dislodged or switch port flap on Mepco AIDS 192.16.16.0/24 subnet."
            ),
            "student_advice": (
                "1. Inspect the blue Cat6 Ethernet cable at the back of the CPU tower.\n"
                "2. Ensure the link indicator light is illuminated solid green/amber.\n"
                "3. If link LED is dark, re-seat the RJ-45 connector until it clicks."
            ),
            "recommended_playbook": "network_self_heal",
            "playbook_title": "Network Stack Self-Heal & Link Diagnostic",
            "est_resolution_time": "10 seconds",
            "auto_remediable": True,
            "confidence": 0.91
        },
        {
            "id": "peripheral_display_issue",
            "name": "Display Resolution / Peripheral Interface Malfunction",
            "regex": r"(monitor|display|hdmi|vga|resolution|no signal|screen flicker|keyboard|mouse|usb)",
            "category": "Peripheral / Display",
            "severity": "Medium",
            "root_cause": (
                "HDMI/DisplayPort cable loose or USB composite human-interface device suspended by OS power management."
            ),
            "student_advice": (
                "1. Verify HDMI cable connection between monitor and rear GPU port.\n"
                "2. Press Windows + Ctrl + Shift + B to restart graphic subsystem.\n"
                "3. Try plugging mouse/keyboard into front USB 3.0 ports."
            ),
            "recommended_playbook": "service_restart",
            "playbook_title": "Restart Lab Display & Device Manager Services",
            "est_resolution_time": "10 seconds",
            "auto_remediable": False,
            "confidence": 0.88
        }
    ]

    @classmethod
    def diagnose(cls, description: str, category: str = "", specs: str = "") -> Dict[str, Any]:
        """
        Analyze issue description and return real-time diagnosis,
        instant student self-help advice, and technician remediation recommendations.
        """
        text = f"{description} {category} {specs}".lower()

        # Score matching patterns
        matches = []
        for pat in cls.PATTERNS:
            found = re.findall(pat["regex"], text)
            if found:
                score = len(found) * pat["confidence"]
                matches.append((score, pat))

        if matches:
            matches.sort(key=lambda x: x[0], reverse=True)
            best_pat = matches[0][1]
            return {
                "matched": True,
                "pattern_id": best_pat["id"],
                "issue_title": best_pat["name"],
                "category": best_pat["category"],
                "severity": best_pat["severity"],
                "root_cause_analysis": best_pat["root_cause"],
                "student_instant_advice": best_pat["student_advice"],
                "recommended_playbook": best_pat["recommended_playbook"],
                "playbook_title": best_pat["playbook_title"],
                "est_resolution_time": best_pat["est_resolution_time"],
                "auto_remediable": best_pat["auto_remediable"],
                "confidence_score": round(best_pat["confidence"] * 100, 1)
            }

        # Default fallback for generalized issues
        return {
            "matched": False,
            "pattern_id": "general_lab_issue",
            "issue_title": f"General Workstation Diagnostic ({category or 'Lab Fault'})",
            "category": category or "Other",
            "severity": "Medium",
            "root_cause_analysis": "Diagnostic engine did not find explicit AI/GPU failure signatures. Standard workstation triage recommended.",
            "student_instant_advice": (
                "1. Save all open work and close unused applications.\n"
                "2. Check if problem persists after restarting the application.\n"
                "3. A Lab Technician will review your ticket and dispatch remote diagnostics."
            ),
            "recommended_playbook": "network_self_heal",
            "playbook_title": "Network Health Sweep & RPC Probe",
            "est_resolution_time": "10 seconds",
            "auto_remediable": True,
            "confidence_score": 75.0
        }


# Singleton engine instance
ai_diagnostic_engine = AIDSLabDiagnosticEngine()
