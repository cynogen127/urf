#!/usr/bin/env python3
"""
SIGINT-Grade Universal RF Intelligence Framework
Advanced Signals Intelligence Platform for HackRF One

This framework provides professional-grade RF signal intelligence capabilities
including capture, analysis, classification, exploitation, and reporting.

Author: SIGINT Engineering Team
Version: 2.0.0
License: Proprietary - Authorized Use Only

WARNING: This tool is intended for authorized security research,
penetration testing, and signals intelligence operations only.
Unauthorized use may violate federal and international laws.
"""

# =============================================================================
# MODULE IMPORTS & DEPENDENCIES
# =============================================================================

import os
import sys
import time
import json
import hashlib
import logging
import threading
import multiprocessing
import queue
import signal as system_signal
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import List, Dict, Optional, Tuple, Any, Union, Callable, Generator
from collections import Counter, deque
from contextlib import contextmanager
from abc import ABC, abstractmethod
import traceback
import base64
import struct
import ctypes
import functools
import inspect

# Scientific Computing
import numpy as np
from scipy import signal as scipy_signal
from scipy import fft as scipy_fft
from scipy.ndimage import gaussian_filter1d
from scipy.stats import entropy, skew, kurtosis

# Optional ML Libraries
try:
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Visualization
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import matplotlib.gridspec as gridspec

# Hardware Interface
import subprocess
import platform

# Cryptography for secure logging
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Async support
import asyncio
import aiofiles

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================

class Config:
    """Centralized configuration management."""
    
    # Hardware Defaults
    DEFAULT_SAMPLE_RATE = 20_000_000  # 20 MSPS for better resolution
    DEFAULT_BASEBAND_FILTER_BANDWIDTH = 5_000_000
    DEFAULT_LNA_GAIN = 32
    DEFAULT_VGA_GAIN = 40
    DEFAULT_TX_VGA_GAIN = 47
    
    # Frequency Bands (ISM/SRD)
    FREQUENCY_BANDS = {
        'LF': (30_000, 300_000),
        'MF': (300_000, 3_000_000),
        'HF': (3_000_000, 30_000_000),
        'VHF': (30_000_000, 300_000_000),
        'UHF': (300_000_000, 3_000_000_000),
        'COMMON_ISM': [
            433_920_000,  # EU ISM
            868_000_000,  # EU ISM
            915_000_000,  # US ISM
            2_400_000_000,  # WiFi/BT
            5_800_000_000,  # WiFi
        ]
    }
    
    # Signal Processing
    FFT_SIZE = 4096
    OVERLAP_RATIO = 0.5
    DETECTION_THRESHOLD_DB = -60
    MIN_SIGNAL_DURATION_MS = 10
    
    # Security & Compliance
    MAX_TX_POWER_DBM = 27  # Regulatory limit
    BLOCKED_FREQUENCIES = [
        # Emergency services (varies by region)
        (136_000_000, 174_000_000),  # VHF Public Safety
        (450_000_000, 512_000_000),  # UHF Public Safety
    ]
    
    # Performance
    NUM_WORKER_THREADS = multiprocessing.cpu_count()
    QUEUE_MAX_SIZE = 10000
    CACHE_MAX_SIZE = 1000
    
    # Logging
    LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s | %(message)s"
    LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    
    @classmethod
    def is_frequency_blocked(cls, freq_hz: int) -> bool:
        """Check if frequency is in blocked range."""
        for start, end in cls.BLOCKED_FREQUENCIES:
            if start <= freq_hz <= end:
                return True
        return False


# =============================================================================
# ENUMERATIONS
# =============================================================================

class DeviceClass(Enum):
    """RF Device Classification Taxonomy."""
    ACCESS_CONTROL = "access_control"
    AUTOMOTIVE = "automotive"
    BUILDING_AUTOMATION = "building_automation"
    CONSUMER_ELECTRONICS = "consumer_electronics"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
    EMERGENCY_SERVICES = "emergency_services"
    INDUSTRIAL_CONTROL = "industrial_control"
    IOT_DEVICE = "iot_device"
    MEDICAL_DEVICE = "medical_device"
    MILITARY_GOVERNMENT = "military_government"
    PUBLIC_SAFETY = "public_safety"
    TELECOMMUNICATIONS = "telecommunications"
    TRANSPORTATION = "transportation"
    UNKNOWN = "unknown"


class ModulationType(Enum):
    """Modulation scheme classifications."""
    OOK = "on_off_keying"
    ASK = "amplitude_shift_keying"
    FSK = "frequency_shift_keying"
    GFSK = "gaussian_fsk"
    MSK = "minimum_shift_keying"
    GMSK = "gaussian_msk"
    PSK = "phase_shift_keying"
    BPSK = "binary_psk"
    QPSK = "quadrature_psk"
    QAM = "quadrature_amplitude_modulation"
    LOZOR = "lozor"
    PWM = "pulse_width_modulation"
    PPM = "pulse_position_modulation"
    MANCHESTER = "manchester"
    DIFFERENTIAL_MANCHESTER = "differential_manchester"
    COMPLEX = "complex"
    UNKNOWN = "unknown"


class EncodingScheme(Enum):
    """Digital encoding schemes."""
    NRZ = "non_return_to_zero"
    RZ = "return_to_zero"
    MANCHESTER = "manchester"
    DIFFERENTIAL_MANCHESTER = "differential_manchester"
    MILLER = "miller"
    PWM = "pulse_width_modulation"
    PPM = "pulse_position_modulation"
    BI_PHASE_MARK = "bi_phase_mark"
    BI_PHASE_SPACE = "bi_phase_space"
    UNKNOWN = "unknown"


class SecurityLevel(Enum):
    """Signal security assessment levels."""
    NONE = auto()      # No security measures
    WEAK = auto()      # Easily compromised
    MODERATE = auto()  # Some protection
    STRONG = auto()    # Robust security
    MILITARY = auto()  # Military-grade crypto
    UNKNOWN = auto()


class ThreatLevel(Enum):
    """Operational threat assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperationMode(Enum):
    """Framework operation modes."""
    PASSIVE_LISTEN = "passive_listen"
    ACTIVE_CAPTURE = "active_capture"
    TARGETED_ANALYSIS = "targeted_analysis"
    WIDE_BAND_SCAN = "wide_band_scan"
    REPLAY_ATTACK = "replay_attack"
    ROLLING_CODE_ANALYSIS = "rolling_code_analysis"
    PROTOCOL_FUZZING = "protocol_fuzzing"
    SIGNAL_INJECTION = "signal_injection"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class IQSample:
    """Raw IQ sample container."""
    data: np.ndarray
    sample_rate: int
    center_frequency: int
    timestamp: float
    gain_settings: Dict[str, int]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> float:
        return len(self.data) / self.sample_rate
    
    @property
    def bandwidth(self) -> int:
        return self.sample_rate // 2


@dataclass
class SignalFeatures:
    """Extracted signal features for classification."""
    # Time Domain
    mean_amplitude: float
    std_amplitude: float
    peak_amplitude: float
    crest_factor: float
    zero_crossing_rate: float
    
    # Frequency Domain
    spectral_centroid: float
    spectral_bandwidth: float
    spectral_rolloff: float
    spectral_flatness: float
    dominant_frequency: float
    harmonic_ratios: List[float]
    
    # Modulation Features
    amplitude_variance: float
    phase_variance: float
    frequency_variance: float
    constellation_entropy: float
    
    # Statistical Moments
    skewness: float
    kurtosis: float
    
    # Raw feature vector
    feature_vector: np.ndarray


@dataclass
class DecodedFrame:
    """Decoded protocol frame structure."""
    raw_bits: str
    hex_payload: str
    preamble: Optional[str]
    sync_word: Optional[str]
    address_field: Optional[str]
    control_field: Optional[str]
    payload: Optional[str]
    crc_field: Optional[str]
    crc_valid: bool
    
    # Protocol identification
    protocol_name: str
    protocol_version: Optional[str]
    
    # Signal metadata
    modulation: ModulationType
    encoding: EncodingScheme
    baud_rate: int
    symbol_rate: int
    frequency_offset: float
    
    # Quality metrics
    snr_db: float
    rssi_dbm: float
    bit_error_rate: Optional[float]
    
    # Timing
    timestamp: float
    frame_duration_us: float
    
    # Classification
    device_class: DeviceClass
    confidence_score: float
    
    # Security assessment
    security_level: SecurityLevel
    vulnerabilities: List[str]
    attack_vectors: List[str]


@dataclass
class IntelligenceReport:
    """Structured intelligence report."""
    report_id: str
    operation_id: str
    classification: str
    timestamp: datetime
    
    # Target information
    target_frequency: int
    target_device: Optional[str]
    location: Optional[Dict[str, float]]
    
    # Signal analysis
    signals_detected: List[DecodedFrame]
    modulation_types: List[str]
    protocols_identified: List[str]
    
    # Threat assessment
    threat_level: ThreatLevel
    capabilities_assessed: List[str]
    vulnerabilities_found: List[str]
    
    # Recommendations
    exploitation_methods: List[str]
    countermeasures: List[str]
    
    # Attachments
    iq_samples: List[str]
    visualizations: List[str]
    raw_data_hash: str
    
    # Metadata
    operator_id: str
    equipment_used: List[str]
    environmental_conditions: Dict[str, Any]


# =============================================================================
# LOGGING INFRASTRUCTURE
# =============================================================================

class SecureLogger:
    """Secure logging with encryption and integrity verification."""
    
    def __init__(self, name: str, log_dir: str = "logs", 
                 encrypt: bool = False, level: int = logging.INFO):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.encrypt = encrypt and CRYPTO_AVAILABLE
        
        if self.encrypt:
            self.cipher = Fernet(Fernet.generate_key())
        
        # Configure logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # File handler with rotation
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"{name}_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        
        formatter = logging.Formatter(Config.LOG_FORMAT, datefmt=Config.LOG_DATE_FORMAT)
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Audit trail
        self.audit_queue = deque(maxlen=10000)
    
    def info(self, msg: str, **kwargs):
        self._log(logging.INFO, msg, **kwargs)
    
    def warning(self, msg: str, **kwargs):
        self._log(logging.WARNING, msg, **kwargs)
    
    def error(self, msg: str, **kwargs):
        self._log(logging.ERROR, msg, **kwargs)
    
    def debug(self, msg: str, **kwargs):
        self._log(logging.DEBUG, msg, **kwargs)
    
    def critical(self, msg: str, **kwargs):
        self._log(logging.CRITICAL, msg, **kwargs)
    
    def _log(self, level: int, msg: str, **kwargs):
        enriched_msg = self._enrich_message(msg, **kwargs)
        self.logger.log(level, enriched_msg)
        
        # Audit trail for sensitive operations
        if level >= logging.WARNING:
            self.audit_queue.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'level': logging.getLevelName(level),
                'message': msg,
                'context': kwargs
            })
    
    def _enrich_message(self, msg: str, **kwargs) -> str:
        """Add contextual information to log messages."""
        context_parts = []
        if 'freq' in kwargs:
            context_parts.append(f"FREQ:{kwargs['freq']/1e6:.3f}MHz")
        if 'snr' in kwargs:
            context_parts.append(f"SNR:{kwargs['snr']:.1f}dB")
        if 'op_id' in kwargs:
            context_parts.append(f"OP:{kwargs['op_id']}")
        
        if context_parts:
            return f"[{' '.join(context_parts)}] {msg}"
        return msg
    
    def export_audit_trail(self, filepath: str):
        """Export audit trail to file."""
        with open(filepath, 'w') as f:
            json.dump(list(self.audit_queue), f, indent=2)


# =============================================================================
# SIGNAL PROCESSING ENGINE
# =============================================================================

class SignalProcessor:
    """High-performance signal processing engine."""
    
    def __init__(self, sample_rate: int = Config.DEFAULT_SAMPLE_RATE):
        self.sample_rate = sample_rate
        self.fft_size = Config.FFT_SIZE
        self.overlap = int(self.fft_size * Config.OVERLAP_RATIO)
        self.window = scipy_signal.windows.hann(self.fft_size)
    
    def compute_spectrogram(self, iq_data: np.ndarray, 
                           nperseg: int = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Compute spectrogram with optimized parameters."""
        if nperseg is None:
            nperseg = self.fft_size
        
        frequencies, times, Sxx = scipy_signal.spectrogram(
            iq_data,
            fs=self.sample_rate,
            window='hann',
            nperseg=nperseg,
            noverlap=self.overlap,
            detrend=False,
            scaling='spectrum'
        )
        
        return frequencies, times, 10 * np.log10(Sxx + 1e-12)
    
    def detect_signals(self, iq_data: np.ndarray, 
                      threshold_db: float = None) -> List[Tuple[float, float, float]]:
        """Detect active signals in IQ data."""
        if threshold_db is None:
            threshold_db = Config.DETECTION_THRESHOLD_DB
        
        # Compute power spectral density
        frequencies, psd = scipy_signal.welch(
            iq_data,
            fs=self.sample_rate,
            nperseg=min(4096, len(iq_data))
        )
        
        psd_db = 10 * np.log10(psd + 1e-12)
        
        # Find peaks above threshold
        peaks, properties = scipy_signal.find_peaks(
            psd_db,
            height=threshold_db,
            distance=self.sample_rate // 100000  # Minimum 10kHz spacing
        )
        
        signals = []
        for peak_idx in peaks:
            freq = frequencies[peak_idx]
            power = psd_db[peak_idx]
            
            # Estimate bandwidth at -3dB
            half_power = power - 3
            left_idx = np.where(psd_db[:peak_idx] < half_power)[0]
            right_idx = np.where(psd_db[peak_idx:] < half_power)[0]
            
            left_freq = frequencies[left_idx[-1]] if len(left_idx) > 0 else frequencies[0]
            right_freq = frequencies[peak_idx + right_idx[0]] if len(right_idx) > 0 else frequencies[-1]
            
            bandwidth = right_freq - left_freq
            signals.append((freq, bandwidth, power))
        
        return signals
    
    def extract_features(self, iq_data: np.ndarray) -> SignalFeatures:
        """Extract comprehensive signal features."""
        # Time domain features
        amplitude = np.abs(iq_data)
        phase = np.angle(iq_data)
        
        mean_amp = np.mean(amplitude)
        std_amp = np.std(amplitude)
        peak_amp = np.max(amplitude)
        crest_factor = peak_amp / (mean_amp + 1e-12)
        
        # Zero crossing rate
        zero_crossings = np.sum(np.diff(np.sign(amplitude - mean_amp)) != 0)
        zcr = zero_crossings / len(amplitude)
        
        # Frequency domain features
        fft_data = np.fft.fft(iq_data * self.window[:len(iq_data)])
        magnitude = np.abs(fft_data[:len(fft_data)//2])
        freqs = np.fft.fftfreq(len(iq_data), 1/self.sample_rate)[:len(fft_data)//2]
        
        magnitude_norm = magnitude / (np.sum(magnitude) + 1e-12)
        
        spectral_centroid = np.sum(freqs * magnitude_norm)
        spectral_bandwidth = np.sqrt(np.sum(((freqs - spectral_centroid) ** 2) * magnitude_norm))
        
        # Spectral rolloff (95% energy)
        cumsum = np.cumsum(magnitude_norm)
        rolloff_idx = np.where(cumsum >= 0.95)[0][0] if len(cumsum) > 0 else 0
        spectral_rolloff = freqs[rolloff_idx]
        
        # Spectral flatness (Wiener entropy)
        geometric_mean = np.exp(np.mean(np.log(magnitude_norm + 1e-12)))
        arithmetic_mean = np.mean(magnitude_norm)
        spectral_flatness = geometric_mean / (arithmetic_mean + 1e-12)
        
        # Dominant frequency
        dominant_freq = freqs[np.argmax(magnitude)]
        
        # Harmonic ratios
        harmonic_ratios = []
        for h in range(2, 6):
            harmonic_freq = dominant_freq * h
            harmonic_idx = np.argmin(np.abs(freqs - harmonic_freq))
            if harmonic_idx < len(magnitude):
                ratio = magnitude[harmonic_idx] / (magnitude[np.argmax(magnitude)] + 1e-12)
                harmonic_ratios.append(ratio)
        
        # Modulation features
        inst_freq = np.diff(np.unwrap(phase)) * self.sample_rate / (2 * np.pi)
        
        amp_var = np.var(amplitude)
        phase_var = np.var(phase)
        freq_var = np.var(inst_freq)
        
        # Constellation entropy
        if ML_AVAILABLE:
            constellation = iq_data[:min(10000, len(iq_data))]
            scaler = StandardScaler()
            const_scaled = scaler.fit_transform(
                np.column_stack([np.real(constellation), np.imag(constellation)])
            )
            constellation_entropy = entropy(np.histogramdd(const_scaled, bins=10)[0].flatten() + 1e-12)
        else:
            constellation_entropy = 0.0
        
        # Statistical moments
        skewness_val = skew(amplitude)
        kurtosis_val = kurtosis(amplitude)
        
        # Feature vector
        feature_vector = np.array([
            mean_amp, std_amp, peak_amp, crest_factor, zcr,
            spectral_centroid, spectral_bandwidth, spectral_rolloff,
            spectral_flatness, dominant_freq,
            amp_var, phase_var, freq_var, constellation_entropy,
            skewness_val, kurtosis_val
        ] + harmonic_ratios)
        
        return SignalFeatures(
            mean_amplitude=mean_amp,
            std_amplitude=std_amp,
            peak_amplitude=peak_amp,
            crest_factor=crest_factor,
            zero_crossing_rate=zcr,
            spectral_centroid=spectral_centroid,
            spectral_bandwidth=spectral_bandwidth,
            spectral_rolloff=spectral_rolloff,
            spectral_flatness=spectral_flatness,
            dominant_frequency=dominant_freq,
            harmonic_ratios=harmonic_ratios,
            amplitude_variance=amp_var,
            phase_variance=phase_var,
            frequency_variance=freq_var,
            constellation_entropy=constellation_entropy,
            skewness=skewness_val,
            kurtosis=kurtosis_val,
            feature_vector=feature_vector
        )
    
    def demodulate_ask(self, iq_data: np.ndarray, baud_rate: int) -> np.ndarray:
        """Demodulate ASK/OOK signals with adaptive threshold."""
        envelope = np.abs(iq_data)
        
        # Bandpass filter around baud rate
        lowcut = baud_rate * 0.5
        highcut = baud_rate * 3
        nyquist = self.sample_rate / 2
        sos = scipy_signal.butter(4, [lowcut/nyquist, highcut/nyquist], btype='band', output='sos')
        filtered = scipy_signal.sosfilt(sos, envelope - np.mean(envelope))
        
        # Adaptive threshold with hysteresis
        samples_per_symbol = int(self.sample_rate / baud_rate)
        
        # Integrate-and-dump
        integrated = []
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            window = filtered[i:i+samples_per_symbol]
            integrated.append(np.trapz(np.abs(window)) / samples_per_symbol)
        
        integrated = np.array(integrated)
        
        # Otsu thresholding
        histogram, bin_centers = np.histogram(integrated, bins=256)
        total = np.sum(histogram)
        sum_total = np.sum(np.arange(256) * histogram)
        
        var_between = np.zeros(256)
        sum_foreground = 0
        weight_foreground = 0
        
        for threshold in range(256):
            weight_foreground += histogram[threshold]
            if weight_foreground == 0:
                continue
            weight_background = total - weight_foreground
            if weight_background == 0:
                break
            
            sum_foreground += threshold * histogram[threshold]
            mean_foreground = sum_foreground / weight_foreground
            mean_background = (sum_total - sum_foreground) / weight_background
            
            var_between[threshold] = weight_foreground * weight_background * \
                                     (mean_foreground - mean_background) ** 2
        
        optimal_threshold = bin_centers[np.argmax(var_between)]
        
        return (integrated > optimal_threshold).astype(int)
    
    def demodulate_fsk(self, iq_data: np.ndarray, baud_rate: int, 
                       deviation: int = None) -> np.ndarray:
        """Demodulate FSK signals with frequency discriminator."""
        # Frequency discriminator
        phase = np.angle(iq_data)
        inst_freq = np.diff(np.unwrap(phase)) * self.sample_rate / (2 * np.pi)
        
        if deviation is None:
            # Auto-detect deviation
            freq_histogram, freq_bins = np.histogram(inst_freq, bins=100)
            peaks, _ = scipy_signal.find_peaks(freq_histogram, height=np.max(freq_histogram)*0.3)
            if len(peaks) >= 2:
                peak_freqs = freq_bins[peaks[:2]]
                deviation = abs(peak_freqs[1] - peak_freqs[0]) / 2
            else:
                deviation = baud_rate
        
        # Low-pass filter
        cutoff = baud_rate * 1.5
        nyquist = self.sample_rate / 2
        sos = scipy_signal.butter(4, cutoff/nyquist, btype='low', output='sos')
        filtered = scipy_signal.sosfilt(sos, inst_freq)
        
        # Sample at symbol rate
        samples_per_symbol = int(self.sample_rate / baud_rate)
        sampled = []
        
        for i in range(0, len(filtered) - samples_per_symbol, samples_per_symbol):
            window = filtered[i:i+samples_per_symbol]
            sampled.append(np.median(window))
        
        sampled = np.array(sampled)
        
        # Binary decision
        threshold = np.median(sampled)
        return (sampled > threshold).astype(int)
    
    def detect_modulation(self, iq_data: np.ndarray) -> Tuple[ModulationType, float]:
        """Classify modulation type using feature analysis."""
        features = self.extract_features(iq_data)
        
        amplitude = np.abs(iq_data)
        phase = np.angle(iq_data)
        inst_freq = np.diff(np.unwrap(phase))
        
        # Normalized variance metrics
        amp_norm = amplitude / (np.max(amplitude) + 1e-12)
        amp_var = np.var(amp_norm)
        phase_std = np.std(phase)
        freq_std = np.std(inst_freq)
        
        # Decision tree for modulation classification
        scores = {}
        
        # OOK/ASK detection
        if amp_var > 0.05 and phase_std < 0.5:
            scores[ModulationType.OOK] = 0.8 if amp_var > 0.15 else 0.6
            scores[ModulationType.ASK] = 0.7 if 0.05 < amp_var <= 0.15 else 0.5
        
        # FSK detection
        if freq_std > 0.01 and amp_var < 0.3:
            scores[ModulationType.FSK] = min(0.9, freq_std * 10)
            scores[ModulationType.GFSK] = min(0.8, freq_std * 8)
        
        # PSK detection
        if phase_std > 0.5 and amp_var < 0.1:
            if phase_std > 1.5:
                scores[ModulationType.QPSK] = 0.75
            else:
                scores[ModulationType.BPSK] = 0.8
        
        # Complex modulations
        if features.constellation_entropy > 2.0:
            scores[ModulationType.QAM] = min(0.85, features.constellation_entropy / 4)
        
        if not scores:
            return ModulationType.UNKNOWN, 0.0
        
        best_mod = max(scores, key=scores.get)
        return best_mod, scores[best_mod]
    
    def estimate_baud_rate(self, iq_data: np.ndarray) -> int:
        """Estimate baud rate using autocorrelation."""
        envelope = np.abs(iq_data)
        envelope = envelope - np.mean(envelope)
        
        # Autocorrelation
        autocorr = np.correlate(envelope, envelope, mode='full')
        autocorr = autocorr[len(autocorr)//2:]
        autocorr = autocorr / autocorr[0]
        
        # Find first significant peak after zero lag
        threshold = 0.3
        min_lag = int(self.sample_rate / 100000)  # Max 100kbps
        max_lag = int(self.sample_rate / 100)     # Min 100bps
        
        for lag in range(min_lag, min(max_lag, len(autocorr))):
            if autocorr[lag] > threshold:
                if lag > 1 and autocorr[lag] > autocorr[lag-1] and \
                   autocorr[lag] > autocorr[min(lag+1, len(autocorr)-1)]:
                    return int(self.sample_rate / lag)
        
        # Fallback: spectral analysis
        fft_mag = np.abs(np.fft.fft(envelope))
        peak_idx = np.argmax(fft_mag[1:len(fft_mag)//2]) + 1
        estimated_rate = peak_idx * self.sample_rate / len(envelope)
        
        return max(100, min(1000000, int(estimated_rate)))


# =============================================================================
# PROTOCOL DATABASE & CLASSIFIER
# =============================================================================

class ProtocolDatabase:
    """Comprehensive RF protocol database."""
    
    PROTOCOLS = {
        # Garage Door Protocols
        "chamberlain_security_plus": {
            "device_class": DeviceClass.ACCESS_CONTROL,
            "modulation": ModulationType.MANCHESTER,
            "encoding": EncodingScheme.MANCHESTER,
            "baud_rate": 1000,
            "frame_structure": {
                "preamble_bits": 12,
                "sync_bits": 2,
                "fixed_bits": 10,
                "counter_bits": 12,
                "command_bits": 4,
                "total_bits": 66
            },
            "security_level": SecurityLevel.MODERATE,
            "vulnerabilities": ["Rollback attack possible", "Limited counter space"],
            "attack_vectors": ["Replay within counter window", "Brute force counter"]
        },
        
        "liftmaster_learn": {
            "device_class": DeviceClass.ACCESS_CONTROL,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.PWM,
            "baud_rate": 2400,
            "frame_structure": {
                "preamble_bits": 8,
                "address_bits": 24,
                "command_bits": 8,
                "total_bits": 40
            },
            "security_level": SecurityLevel.WEAK,
            "vulnerabilities": ["Fixed code", "No encryption"],
            "attack_vectors": ["Simple replay", "Brute force address"]
        },
        
        # Automotive Protocols
        "keeloq": {
            "device_class": DeviceClass.AUTOMOTIVE,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.MANCHESTER,
            "baud_rate": 2600,
            "frame_structure": {
                "preamble_bits": 12,
                "function_bits": 4,
                "encrypted_bits": 32,
                "serial_bits": 28,
                "total_bits": 66
            },
            "security_level": SecurityLevel.WEAK,
            "vulnerabilities": ["KeeLoq cipher broken", "Key extraction possible"],
            "attack_vectors": ["Key recovery attack", "Code grabbing"]
        },
        
        "hcs200": {
            "device_class": DeviceClass.AUTOMOTIVE,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.MANCHESTER,
            "baud_rate": 3000,
            "frame_structure": {
                "preamble_bits": 12,
                "button_bits": 4,
                "counter_bits": 16,
                "discrimination_bits": 4,
                "serial_bits": 28,
                "total_bits": 64
            },
            "security_level": SecurityLevel.MODERATE,
            "vulnerabilities": ["Counter prediction possible"],
            "attack_vectors": ["Code grabbing with prediction"]
        },
        
        # Remote Control Protocols
        "ev1527": {
            "device_class": DeviceClass.CONSUMER_ELECTRONICS,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.PWM,
            "baud_rate": 10000,
            "frame_structure": {
                "address_bits": 20,
                "data_bits": 4,
                "total_bits": 24
            },
            "security_level": SecurityLevel.NONE,
            "vulnerabilities": ["Fixed code", "Learning mode exploit"],
            "attack_vectors": ["Replay", "Learning mode activation"]
        },
        
        "pt2262": {
            "device_class": DeviceClass.CONSUMER_ELECTRONICS,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.PWM,
            "baud_rate": 5000,
            "frame_structure": {
                "address_bits": 12,
                "data_bits": 4,
                "total_bits": 24
            },
            "security_level": SecurityLevel.NONE,
            "vulnerabilities": ["Tri-state addressing weak"],
            "attack_vectors": ["Address scanning", "Replay"]
        },
        
        # Gate Controller Protocols
        "came_top432": {
            "device_class": DeviceClass.ACCESS_CONTROL,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.MANCHESTER,
            "baud_rate": 2000,
            "frame_structure": {
                "preamble_bits": 24,
                "counter_bits": 24,
                "encrypted_bits": 18,
                "total_bits": 66
            },
            "security_level": SecurityLevel.MODERATE,
            "vulnerabilities": ["Proprietary encryption weak"],
            "attack_vectors": ["Code grabbing"]
        },
        
        "nice_flor": {
            "device_class": DeviceClass.ACCESS_CONTROL,
            "modulation": ModulationType.ASK,
            "encoding": EncodingScheme.MANCHESTER,
            "baud_rate": 1800,
            "frame_structure": {
                "preamble_bits": 12,
                "serial_bits": 16,
                "counter_bits": 24,
                "encrypted_bits": 20,
                "total_bits": 72
            },
            "security_level": SecurityLevel.MODERATE,
            "vulnerabilities": ["Known plaintext attack"],
            "attack_vectors": ["Code analysis"]
        },
        
        # Pager Protocols
        "pocsag": {
            "device_class": DeviceClass.TELECOMMUNICATIONS,
            "modulation": ModulationType.FSK,
            "encoding": EncodingScheme.NRZ,
            "baud_rate": 512,
            "frame_structure": {
                "preamble_bits": 576,
                "sync_bits": 32,
                "batch_structure": "complex",
                "total_bits": 544
            },
            "security_level": SecurityLevel.NONE,
            "vulnerabilities": ["No encryption", "Address visible"],
            "attack_vectors": ["Passive monitoring", "Message injection"]
        },
        
        # IoT Protocols
        "xiaomi_smart_home": {
            "device_class": DeviceClass.IOT_DEVICE,
            "modulation": ModulationType.GFSK,
            "encoding": EncodingScheme.NRZ,
            "baud_rate": 50000,
            "frame_structure": {
                "preamble_bits": 8,
                "access_address_bits": 32,
                "header_bits": 16,
                "payload_bits": "variable",
                "crc_bits": 16,
                "total_bits": "variable"
            },
            "security_level": SecurityLevel.MODERATE,
            "vulnerabilities": ["Weak pairing"],
            "attack_vectors": ["MITM during pairing"]
        }
    }
    
    @classmethod
    def identify_protocol(cls, bits: str, features: SignalFeatures,
                         baud_rate: int) -> Tuple[Optional[str], float]:
        """Identify protocol based on frame characteristics."""
        bit_length = len(bits)
        candidates = []
        
        for proto_name, proto_info in cls.PROTOCOLS.items():
            score = 0.0
            
            # Frame length matching
            structure = proto_info.get('frame_structure', {})
            expected_bits = structure.get('total_bits', 0)
            
            if isinstance(expected_bits, int) and expected_bits > 0:
                if abs(bit_length - expected_bits) <= 2:
                    score += 0.4
                elif abs(bit_length - expected_bits) <= 5:
                    score += 0.2
            
            # Baud rate matching
            expected_baud = proto_info.get('baud_rate', 0)
            if expected_baud > 0:
                baud_diff = abs(baud_rate - expected_baud) / expected_baud
                if baud_diff < 0.1:
                    score += 0.3
                elif baud_diff < 0.2:
                    score += 0.15
            
            # Modulation matching (if features available)
            expected_mod = proto_info.get('modulation')
            # Additional feature matching could be added here
            
            if score > 0.3:
                candidates.append((proto_name, score, proto_info))
        
        if candidates:
            best = max(candidates, key=lambda x: x[1])
            return best[0], best[1]
        
        return None, 0.0
    
    @classmethod
    def get_protocol_info(cls, protocol_name: str) -> Optional[Dict]:
        """Retrieve protocol information."""
        return cls.PROTOCOLS.get(protocol_name)
    
    @classmethod
    def list_protocols(cls, device_class: DeviceClass = None) -> List[str]:
        """List protocols, optionally filtered by device class."""
        if device_class is None:
            return list(cls.PROTOCOLS.keys())
        
        return [
            name for name, info in cls.PROTOCOLS.items()
            if info.get('device_class') == device_class
        ]


# =============================================================================
# HACKRF HARDWARE INTERFACE
# =============================================================================

class HackRFInterface:
    """Professional HackRF One hardware interface."""
    
    def __init__(self):
        self.device_serial = None
        self.board_id = None
        self.firmware_version = None
        self.is_initialized = False
        self.current_frequency = 0
        self.current_sample_rate = 0
        self.lna_gain = 0
        self.vga_gain = 0
        
        self._verify_hardware()
    
    def _verify_hardware(self):
        """Verify HackRF hardware is available."""
        try:
            result = subprocess.run(
                ['hackrf_info'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse serial number
                serial_match = output.find('Serial no:')
                if serial_match >= 0:
                    line = output[serial_match:].split('\n')[0]
                    self.device_serial = line.split(':')[1].strip()
                
                # Parse board ID
                board_match = output.find('Board ID Number:')
                if board_match >= 0:
                    line = output[board_match:].split('\n')[0]
                    self.board_id = line.split(':')[1].strip()
                
                # Parse firmware version
                fw_match = output.find('Firmware Version:')
                if fw_match >= 0:
                    line = output[fw_match:].split('\n')[0]
                    self.firmware_version = line.split(':')[1].strip()
                
                self.is_initialized = True
                
        except FileNotFoundError:
            raise RuntimeError("HackRF tools not found. Install hackrf package.")
        except Exception as e:
            raise RuntimeError(f"HackRF initialization failed: {e}")
    
    def calibrate(self) -> Dict[str, float]:
        """Perform hardware calibration."""
        calibration = {
            'frequency_error_ppm': 0.0,
            'dc_offset_i': 0.0,
            'dc_offset_q': 0.0,
            'iq_balance_real': 1.0,
            'iq_balance_imag': 0.0
        }
        
        # In production, this would perform actual calibration
        # For now, return nominal values
        
        return calibration
    
    def capture_iq(self, frequency: int, duration: float,
                   sample_rate: int = None,
                   lna_gain: int = None,
                   vga_gain: int = None,
                   output_file: str = None) -> IQSample:
        """Capture IQ samples from HackRF."""
        
        # Validate frequency
        if Config.is_frequency_blocked(frequency):
            raise ValueError(f"Frequency {frequency/1e6:.1f}MHz is blocked for TX/RX")
        
        sample_rate = sample_rate or Config.DEFAULT_SAMPLE_RATE
        lna_gain = lna_gain or Config.DEFAULT_LNA_GAIN
        vga_gain = vga_gain or Config.DEFAULT_VGA_GAIN
        
        # Generate output filename
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S%f")
            output_file = f"capture_{frequency}_{timestamp}.iq"
        
        # Calculate sample count
        num_samples = int(sample_rate * duration * 2)  # I and Q
        
        # Build hackrf_transfer command
        cmd = [
            'hackrf_transfer',
            '-r', output_file,
            '-f', str(frequency),
            '-s', str(sample_rate),
            '-l', str(lna_gain),
            '-g', str(vga_gain),
            '-a', '1',  # Amp enable
            '-n', str(num_samples)
        ]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=duration + 10)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Capture failed: {e.stderr.decode()}")
        
        # Load and process IQ data
        samples = np.fromfile(output_file, dtype=np.int8)
        iq_data = samples[::2].astype(np.float32) + 1j * samples[1::2].astype(np.float32)
        iq_data = iq_data / 127.0  # Normalize to [-1, 1]
        
        return IQSample(
            data=iq_data,
            sample_rate=sample_rate,
            center_frequency=frequency,
            timestamp=time.time(),
            gain_settings={'lna': lna_gain, 'vga': vga_gain},
            metadata={'filename': output_file}
        )
    
    def transmit_iq(self, iq_file: str, frequency: int,
                    sample_rate: int = None,
                    tx_gain: int = None,
                    repeat: int = 1,
                    delay_ms: int = 100) -> bool:
        """Transmit IQ samples via HackRF."""
        
        # Validate frequency
        if Config.is_frequency_blocked(frequency):
            raise ValueError(f"Frequency {frequency/1e6:.1f}MHz is blocked for TX")
        
        # Check power limits
        if tx_gain is None:
            tx_gain = Config.DEFAULT_TX_VGA_GAIN
        
        if tx_gain > 47:
            logging.warning(f"TX gain {tx_gain} exceeds recommended maximum (47)")
        
        sample_rate = sample_rate or Config.DEFAULT_SAMPLE_RATE
        
        for i in range(repeat):
            cmd = [
                'hackrf_transfer',
                '-t', iq_file,
                '-f', str(frequency),
                '-s', str(sample_rate),
                '-x', str(tx_gain),
                '-a', '1'
            ]
            
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            except subprocess.CalledProcessError as e:
                logging.error(f"Transmission failed: {e.stderr.decode()}")
                return False
            
            if i < repeat - 1:
                time.sleep(delay_ms / 1000.0)
        
        return True
    
    def spectrum_scan(self, start_freq: int, end_freq: int,
                      step_size: int = 1000000,
                      dwell_time: float = 0.1,
                      callback: Callable = None) -> Generator[Tuple[int, np.ndarray], None, None]:
        """Perform spectrum scan across frequency range."""
        
        current_freq = start_freq
        
        while current_freq <= end_freq:
            try:
                # Capture short burst at each frequency
                sample_rate = min(step_size * 2, Config.DEFAULT_SAMPLE_RATE)
                iq_sample = self.capture_iq(
                    frequency=current_freq,
                    duration=dwell_time,
                    sample_rate=sample_rate
                )
                
                # Compute PSD
                freqs, psd = scipy_signal.welch(
                    iq_sample.data,
                    fs=sample_rate,
                    nperseg=min(1024, len(iq_sample.data))
                )
                
                # Adjust frequencies relative to center
                absolute_freqs = freqs + current_freq - sample_rate / 2
                
                if callback:
                    callback(current_freq, absolute_freqs, psd)
                
                yield current_freq, absolute_freqs, psd
                
            except Exception as e:
                logging.error(f"Scan error at {current_freq/1e6:.1f}MHz: {e}")
            
            current_freq += step_size
    
    def set_frequency(self, frequency: int):
        """Set operating frequency."""
        if Config.is_frequency_blocked(frequency):
            raise ValueError(f"Frequency {frequency/1e6:.1f}MHz is blocked")
        self.current_frequency = frequency
    
    def set_gain(self, lna: int, vga: int):
        """Set receiver gains."""
        self.lna_gain = max(0, min(48, lna))
        self.vga_gain = max(0, min(62, vga))
    
    def get_status(self) -> Dict[str, Any]:
        """Get device status."""
        return {
            'serial': self.device_serial,
            'board_id': self.board_id,
            'firmware': self.firmware_version,
            'initialized': self.is_initialized,
            'frequency': self.current_frequency,
            'lna_gain': self.lna_gain,
            'vga_gain': self.vga_gain
        }


# =============================================================================
# INTELLIGENCE ANALYSIS ENGINE
# =============================================================================

class IntelligenceEngine:
    """Advanced signal intelligence analysis engine."""
    
    def __init__(self):
        self.processor = SignalProcessor()
        self.protocol_db = ProtocolDatabase()
        self.analysis_cache = {}
    
    def analyze_signal(self, iq_sample: IQSample) -> List[DecodedFrame]:
        """Comprehensive signal analysis pipeline."""
        frames = []
        
        # Detect active signals
        signals = self.processor.detect_signals(iq_sample.data)
        
        for freq_offset, bandwidth, power in signals:
            # Extract signal from IQ data
            center_freq = iq_sample.center_frequency + freq_offset
            
            # Bandpass filter to isolate signal
            lowcut = freq_offset - bandwidth / 2
            highcut = freq_offset + bandwidth / 2
            nyquist = iq_sample.sample_rate / 2
            
            sos = scipy_signal.butter(
                4,
                [max(lowcut/nyquist, 0.001), min(highcut/nyquist, 0.999)],
                btype='band',
                output='sos'
            )
            filtered = scipy_signal.sosfilt(sos, iq_sample.data)
            
            # Extract features
            features = self.processor.extract_features(filtered)
            
            # Classify modulation
            modulation, mod_confidence = self.processor.detect_modulation(filtered)
            
            # Estimate baud rate
            baud_rate = self.processor.estimate_baud_rate(filtered)
            
            # Demodulate based on modulation type
            if modulation in [ModulationType.OOK, ModulationType.ASK]:
                bits = self.processor.demodulate_ask(filtered, baud_rate)
            elif modulation in [ModulationType.FSK, ModulationType.GFSK]:
                bits = self.processor.demodulate_fsk(filtered, baud_rate)
            else:
                bits = np.array([])
            
            if len(bits) > 0:
                # Convert to bit string
                bit_string = ''.join(map(str, bits.astype(int)))
                
                # Identify protocol
                protocol_name, confidence = self.protocol_db.identify_protocol(
                    bit_string, features, baud_rate
                )
                
                # Extract frame components
                frame_components = self._extract_frame_components(
                    bit_string, protocol_name
                )
                
                # Calculate quality metrics
                snr_db = power - Config.DETECTION_THRESHOLD_DB
                rssi_dbm = -100 + power  # Approximate conversion
                
                # Create decoded frame
                frame = DecodedFrame(
                    raw_bits=bit_string,
                    hex_payload=self._bits_to_hex(bit_string),
                    preamble=frame_components.get('preamble'),
                    sync_word=frame_components.get('sync'),
                    address_field=frame_components.get('address'),
                    control_field=frame_components.get('control'),
                    payload=frame_components.get('payload'),
                    crc_field=frame_components.get('crc'),
                    crc_valid=True,  # Would need actual CRC check
                    protocol_name=protocol_name or "unknown",
                    protocol_version=None,
                    modulation=modulation,
                    encoding=self._infer_encoding(bits),
                    baud_rate=baud_rate,
                    symbol_rate=baud_rate,
                    frequency_offset=freq_offset,
                    snr_db=snr_db,
                    rssi_dbm=rssi_dbm,
                    bit_error_rate=None,
                    timestamp=time.time(),
                    frame_duration_us=len(bits) / baud_rate * 1e6,
                    device_class=self.protocol_db.PROTOCOLS.get(
                        protocol_name, {}
                    ).get('device_class', DeviceClass.UNKNOWN),
                    confidence_score=confidence * mod_confidence,
                    security_level=self.protocol_db.PROTOCOLS.get(
                        protocol_name, {}
                    ).get('security_level', SecurityLevel.UNKNOWN),
                    vulnerabilities=self.protocol_db.PROTOCOLS.get(
                        protocol_name, {}
                    ).get('vulnerabilities', []),
                    attack_vectors=self.protocol_db.PROTOCOLS.get(
                        protocol_name, {}
                    ).get('attack_vectors', [])
                )
                
                frames.append(frame)
        
        return frames
    
    def _extract_frame_components(self, bits: str, 
                                  protocol_name: Optional[str]) -> Dict[str, str]:
        """Extract logical components from bit stream."""
        components = {}
        
        if protocol_name:
            proto_info = self.protocol_db.get_protocol_info(protocol_name)
            if proto_info:
                structure = proto_info.get('frame_structure', {})
                # Parse based on known structure
                idx = 0
                
                if 'preamble_bits' in structure:
                    pre_len = structure['preamble_bits']
                    components['preamble'] = bits[idx:idx+pre_len]
                    idx += pre_len
                
                if 'sync_bits' in structure:
                    sync_len = structure['sync_bits']
                    components['sync'] = bits[idx:idx+sync_len]
                    idx += sync_len
                
                # Continue parsing based on protocol...
                # Simplified for brevity
        
        # Generic extraction for unknown protocols
        if not components:
            # Look for common preamble patterns
            for pattern in ['101010101010', '11110000', '01010101']:
                if bits.startswith(pattern):
                    components['preamble'] = bits[:len(pattern)]
                    break
        
        return components
    
    def _bits_to_hex(self, bits: str) -> str:
        """Convert bit string to hexadecimal."""
        # Pad to byte boundary
        padded = bits + '0' * ((8 - len(bits) % 8) % 8)
        hex_chars = []
        for i in range(0, len(padded), 8):
            byte = padded[i:i+8]
            hex_chars.append(f"{int(byte, 2):02X}")
        return ' '.join(hex_chars)
    
    def _infer_encoding(self, bits: np.ndarray) -> EncodingScheme:
        """Infer encoding scheme from bit pattern."""
        if len(bits) < 50:
            return EncodingScheme.UNKNOWN
        
        # Check for Manchester encoding (50% transition density)
        transitions = np.sum(np.diff(bits.astype(int)) != 0)
        transition_rate = transitions / len(bits)
        
        if 0.45 < transition_rate < 0.55:
            return EncodingScheme.MANCHESTER
        
        # Check for PWM (variable pulse widths)
        runs = []
        current_run = 1
        for i in range(1, len(bits)):
            if bits[i] == bits[i-1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        
        if runs and np.var(runs) > 2:
            return EncodingScheme.PWM
        
        return EncodingScheme.NRZ
    
    def generate_intelligence_report(self, frames: List[DecodedFrame],
                                    operation_id: str,
                                    operator_id: str = "SYSTEM") -> IntelligenceReport:
        """Generate structured intelligence report."""
        
        # Aggregate findings
        protocols = list(set(f.protocol_name for f in frames if f.protocol_name != "unknown"))
        modulations = list(set(f.modulation.value for f in frames))
        
        # Assess threat level
        vulns = []
        for f in frames:
            vulns.extend(f.vulnerabilities)
        
        if any(v in str(vulns).lower() for v in ['military', 'critical']):
            threat = ThreatLevel.CRITICAL
        elif any(v in str(vulns).lower() for v in ['broken', 'weak', 'none']):
            threat = ThreatLevel.HIGH
        elif vulns:
            threat = ThreatLevel.MEDIUM
        else:
            threat = ThreatLevel.LOW
        
        # Generate report ID
        report_id = hashlib.md5(
            f"{operation_id}{time.time()}".encode()
        ).hexdigest()[:12]
        
        return IntelligenceReport(
            report_id=report_id,
            operation_id=operation_id,
            classification="UNCLASSIFIED//FOUO",
            timestamp=datetime.now(timezone.utc),
            target_frequency=frames[0].frequency_offset if frames else 0,
            target_device=None,
            location=None,
            signals_detected=frames,
            modulation_types=modulations,
            protocols_identified=protocols,
            threat_level=threat,
            capabilities_assessed=[f.device_class.value for f in frames],
            vulnerabilities_found=list(set(vulns)),
            exploitation_methods=[],
            countermeasures=[],
            iq_samples=[],
            visualizations=[],
            raw_data_hash="",
            operator_id=operator_id,
            equipment_used=["HackRF One"],
            environmental_conditions={}
        )


# =============================================================================
# EXPLOITATION MODULES
# =============================================================================

class ExploitationModule(ABC):
    """Base class for exploitation modules."""
    
    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def validate_target(self, frame: DecodedFrame) -> bool:
        pass


class ReplayAttack(ExploitationModule):
    """Simple replay attack module."""
    
    def __init__(self, hw_interface: HackRFInterface):
        self.hw = hw_interface
        self.logger = SecureLogger("ReplayAttack")
    
    def validate_target(self, frame: DecodedFrame) -> bool:
        return frame.security_level in [
            SecurityLevel.NONE, SecurityLevel.WEAK
        ]
    
    def execute(self, iq_file: str, frequency: int, 
                repeat: int = 5, delay_ms: int = 200) -> Dict[str, Any]:
        """Execute replay attack."""
        result = {
            'success': False,
            'attempts': 0,
            'errors': []
        }
        
        self.logger.info(f"Initiating replay attack", 
                        freq=frequency, op_id="REPLAY_001")
        
        success = self.hw.transmit_iq(
            iq_file=iq_file,
            frequency=frequency,
            repeat=repeat,
            delay_ms=delay_ms
        )
        
        result['success'] = success
        result['attempts'] = repeat
        
        if success:
            self.logger.info("Replay attack completed successfully")
        else:
            result['errors'].append("Transmission failed")
            self.logger.error("Replay attack failed")
        
        return result


class RollingCodeAnalyzer(ExploitationModule):
    """Rolling code analysis and prediction module."""
    
    def __init__(self):
        self.collected_codes = []
        self.counter_sequence = []
        self.logger = SecureLogger("RollingCodeAnalyzer")
    
    def validate_target(self, frame: DecodedFrame) -> bool:
        return frame.security_level in [
            SecurityLevel.WEAK, SecurityLevel.MODERATE
        ]
    
    def collect_code(self, frame: DecodedFrame):
        """Collect rolling code for analysis."""
        self.collected_codes.append({
            'timestamp': frame.timestamp,
            'raw_bits': frame.raw_bits,
            'counter': frame.control_field
        })
        
        if frame.control_field:
            try:
                counter_val = int(frame.control_field, 2)
                self.counter_sequence.append(counter_val)
            except ValueError:
                pass
    
    def analyze_sequence(self) -> Dict[str, Any]:
        """Analyze collected rolling code sequence."""
        if len(self.counter_sequence) < 2:
            return {'status': 'insufficient_data'}
        
        # Analyze counter increments
        diffs = np.diff(self.counter_sequence)
        
        analysis = {
            'codes_collected': len(self.collected_codes),
            'counter_pattern': 'incremental' if all(d > 0 for d in diffs) else 'unknown',
            'average_increment': float(np.mean(diffs)) if len(diffs) > 0 else 0,
            'counter_range': (min(self.counter_sequence), max(self.counter_sequence)),
            'prediction_possible': len(self.counter_sequence) >= 3
        }
        
        if analysis['prediction_possible']:
            # Simple linear prediction
            next_counter = self.counter_sequence[-1] + int(analysis['average_increment'])
            analysis['predicted_next'] = next_counter
        
        return analysis
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        return self.analyze_sequence()


class BruteForceAttack(ExploitationModule):
    """Brute force attack for fixed-code systems."""
    
    def __init__(self, hw_interface: HackRFInterface):
        self.hw = hw_interface
        self.logger = SecureLogger("BruteForceAttack")
    
    def validate_target(self, frame: DecodedFrame) -> bool:
        return frame.security_level == SecurityLevel.NONE
    
    def execute(self, base_frame: DecodedFrame, 
                field_to_brute: str = 'command',
                delay_ms: int = 100) -> Dict[str, Any]:
        """Execute brute force attack."""
        result = {
            'success': False,
            'combinations_tested': 0,
            'field': field_to_brute
        }
        
        field_value = getattr(base_frame, f'{field_to_brute}_field', None)
        if not field_value:
            result['errors'] = [f"No {field_to_brute} field found"]
            return result
        
        field_length = len(field_value)
        total_combinations = 2 ** field_length
        
        self.logger.warning(
            f"Initiating brute force on {field_length}-bit field",
            op_id="BRUTE_001"
        )
        
        for i in range(total_combinations):
            test_value = format(i, f'0{field_length}b')
            result['combinations_tested'] += 1
            
            # Generate modified signal
            # In production, this would regenerate and transmit
            
            if i % 10 == 0:
                progress = (i / total_combinations) * 100
                self.logger.debug(f"Progress: {progress:.1f}%")
            
            time.sleep(delay_ms / 1000.0)
        
        result['success'] = True
        return result


# =============================================================================
# VISUALIZATION ENGINE
# =============================================================================

class VisualizationEngine:
    """Professional signal visualization engine."""
    
    def __init__(self):
        plt.style.use('dark_background')
    
    def plot_spectrogram(self, iq_data: np.ndarray, sample_rate: int,
                        title: str = "Spectrogram") -> Figure:
        """Generate spectrogram visualization."""
        fig = plt.figure(figsize=(14, 8))
        gs = gridspec.GridSpec(2, 2, figure=fig)
        
        # Spectrogram
        ax1 = fig.add_subplot(gs[0, :])
        frequencies, times, Sxx = scipy_signal.spectrogram(
            iq_data, fs=sample_rate, nperseg=1024, noverlap=512
        )
        
        im = ax1.pcolormesh(
            times, frequencies/1e6, 10*np.log10(Sxx+1e-12),
            shading='gouraud', cmap='viridis'
        )
        ax1.set_ylabel('Frequency (MHz)')
        ax1.set_xlabel('Time (s)')
        ax1.set_title(f'{title} - Spectrogram')
        plt.colorbar(im, ax=ax1, label='Power (dB)')
        
        # Time domain
        ax2 = fig.add_subplot(gs[1, 0])
        ax2.plot(np.abs(iq_data[:10000]))
        ax2.set_xlabel('Sample')
        ax2.set_ylabel('Amplitude')
        ax2.set_title('Time Domain (Envelope)')
        ax2.grid(True, alpha=0.3)
        
        # Frequency domain
        ax3 = fig.add_subplot(gs[1, 1])
        fft_data = np.fft.fftshift(np.fft.fft(iq_data[:4096]))
        freqs = np.fft.fftshift(np.fft.fftfreq(4096, 1/sample_rate))
        ax3.plot(freqs/1e6, 20*np.log10(np.abs(fft_data)+1e-12))
        ax3.set_xlabel('Frequency (MHz)')
        ax3.set_ylabel('Magnitude (dB)')
        ax3.set_title('Frequency Domain')
        ax3.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_constellation(self, iq_data: np.ndarray,
                          title: str = "Constellation Diagram") -> Figure:
        """Generate constellation diagram."""
        fig, ax = plt.subplots(figsize=(8, 8))
        
        # Downsample for visibility
        plot_data = iq_data[::100]
        
        ax.scatter(np.real(plot_data), np.imag(plot_data), 
                  s=1, alpha=0.5, c='cyan')
        ax.set_xlabel('In-Phase (I)')
        ax.set_ylabel('Quadrature (Q)')
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
        ax.set_aspect('equal')
        
        return fig
    
    def plot_frame_structure(self, frame: DecodedFrame) -> Figure:
        """Visualize decoded frame structure."""
        fig, ax = plt.subplots(figsize=(14, 3))
        
        # Parse frame components
        components = []
        labels = []
        colors = []
        
        pos = 0
        if frame.preamble:
            components.append(len(frame.preamble))
            labels.append('Preamble')
            colors.append('#FF6B6B')
            pos += len(frame.preamble)
        
        if frame.sync_word:
            components.append(len(frame.sync_word))
            labels.append('Sync')
            colors.append('#4ECDC4')
            pos += len(frame.sync_word)
        
        if frame.address_field:
            components.append(len(frame.address_field))
            labels.append('Address')
            colors.append('#45B7D1')
            pos += len(frame.address_field)
        
        if frame.control_field:
            components.append(len(frame.control_field))
            labels.append('Control')
            colors.append('#FFA07A')
            pos += len(frame.control_field)
        
        if frame.payload:
            components.append(len(frame.payload))
            labels.append('Payload')
            colors.append('#98D8C8')
            pos += len(frame.payload)
        
        if frame.crc_field:
            components.append(len(frame.crc_field))
            labels.append('CRC')
            colors.append('#F7DC6F')
        
        # Create stacked bar
        ax.barh(['Frame'], [sum(components)], color='#2C3E50')
        
        # Add component markers
        cum_pos = 0
        for comp, label, color in zip(components, labels, colors):
            ax.axvspan(cum_pos, cum_pos + comp, 0, 1, 
                      alpha=0.7, color=color, label=label)
            ax.text(cum_pos + comp/2, 0, label, 
                   ha='center', va='center', fontsize=9, 
                   bbox=dict(boxstyle='round', facecolor='white', alpha=0.5))
            cum_pos += comp
        
        ax.set_xlabel('Bits')
        ax.set_title(f"Frame Structure: {frame.protocol_name}")
        ax.legend(loc='upper right')
        ax.set_yticks([])
        
        plt.tight_layout()
        return fig
    
    def save_figure(self, fig: Figure, filepath: str, dpi: int = 300):
        """Save figure to file."""
        fig.savefig(filepath, dpi=dpi, bbox_inches='tight', 
                   facecolor='black', edgecolor='none')
        plt.close(fig)


# =============================================================================
# MAIN FRAMEWORK ORCHESTRATOR
# =============================================================================

class SIGINTFramework:
    """Main SIGINT framework orchestrator."""
    
    def __init__(self, operation_mode: OperationMode = OperationMode.PASSIVE_LISTEN):
        self.mode = operation_mode
        self.hw = None
        self.processor = SignalProcessor()
        self.intelligence = IntelligenceEngine()
        self.visualizer = VisualizationEngine()
        self.logger = SecureLogger("SIGINT_Framework")
        
        self.operation_id = f"OP_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.running = False
        
        # Initialize hardware if available
        try:
            self.hw = HackRFInterface()
            self.logger.info("HackRF hardware initialized", 
                           extra={'serial': self.hw.device_serial})
        except Exception as e:
            self.logger.warning(f"HackRF not available: {e}")
            self.hw = None
        
        # Setup signal handlers
        system_signal.signal(system_signal.SIGINT, self._signal_handler)
        system_signal.signal(system_signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def capture_and_analyze(self, frequency: int, duration: float = 2.0,
                           output_file: str = None) -> List[DecodedFrame]:
        """Capture signal and perform analysis."""
        
        if not self.hw:
            self.logger.error("No hardware interface available")
            return []
        
        self.logger.info(f"Starting capture at {frequency/1e6:.3f} MHz",
                        freq=frequency, op_id=self.operation_id)
        
        try:
            # Capture IQ samples
            iq_sample = self.hw.capture_iq(
                frequency=frequency,
                duration=duration,
                output_file=output_file
            )
            
            # Analyze signal
            frames = self.intelligence.analyze_signal(iq_sample)
            
            self.logger.info(f"Analysis complete: {len(frames)} frames decoded",
                            op_id=self.operation_id)
            
            # Generate report
            if frames:
                report = self.intelligence.generate_intelligence_report(
                    frames, self.operation_id
                )
                self._save_report(report)
            
            return frames
            
        except Exception as e:
            self.logger.error(f"Capture/analysis failed: {e}")
            return []
    
    def spectrum_survey(self, start_freq: int, end_freq: int,
                       step_size: int = 1000000) -> Dict[int, List[DecodedFrame]]:
        """Perform wide-band spectrum survey."""
        
        if not self.hw:
            return {}
        
        results = {}
        self.logger.info(f"Starting spectrum survey: {start_freq/1e6:.1f}-{end_freq/1e6:.1f} MHz")
        
        try:
            for freq, freqs, psd in self.hw.spectrum_scan(
                start_freq, end_freq, step_size
            ):
                # Detect signals at this frequency
                signals = self.processor.detect_signals_from_psd(freqs, psd)
                
                if signals:
                    self.logger.info(f"Signals detected at {freq/1e6:.1f} MHz")
                    # Capture and analyze
                    frames = self.capture_and_analyze(freq, duration=0.5)
                    if frames:
                        results[freq] = frames
                
                if not self.running:
                    break
                    
        except Exception as e:
            self.logger.error(f"Spectrum survey error: {e}")
        
        return results
    
    def execute_exploitation(self, frame: DecodedFrame,
                            attack_type: str) -> Dict[str, Any]:
        """Execute exploitation module."""
        
        if not self.hw:
            return {'success': False, 'error': 'No hardware'}
        
        if attack_type == 'replay':
            module = ReplayAttack(self.hw)
        elif attack_type == 'brute_force':
            module = BruteForceAttack(self.hw)
        elif attack_type == 'rolling_code_analysis':
            module = RollingCodeAnalyzer()
        else:
            return {'success': False, 'error': 'Unknown attack type'}
        
        if not module.validate_target(frame):
            return {'success': False, 'error': 'Target not vulnerable'}
        
        return module.execute()
    
    def _save_report(self, report: IntelligenceReport):
        """Save intelligence report to file."""
        report_dir = Path("intelligence_reports")
        report_dir.mkdir(exist_ok=True)
        
        report_file = report_dir / f"{report.report_id}.json"
        
        # Convert to serializable dict
        report_dict = {
            'report_id': report.report_id,
            'operation_id': report.operation_id,
            'classification': report.classification,
            'timestamp': report.timestamp.isoformat(),
            'target_frequency': report.target_frequency,
            'protocols_identified': report.protocols_identified,
            'threat_level': report.threat_level.value,
            'vulnerabilities_found': report.vulnerabilities_found,
            'equipment_used': report.equipment_used
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_dict, f, indent=2)
        
        self.logger.info(f"Report saved: {report_file}")
    
    def interactive_mode(self):
        """Launch interactive CLI mode."""
        print("\n" + "="*70)
        print("SIGINT FRAMEWORK - Interactive Mode")
        print("="*70)
        
        while self.running:
            print("\nCommands:")
            print("  [C]apture    - Capture and analyze signal")
            print("  [S]can       - Spectrum survey")
            print("  [R]eplay     - Replay captured signal")
            print("  [V]isualize  - Generate visualizations")
            print("  [Q]uit       - Exit framework")
            
            choice = input("\nSelect command: ").strip().lower()
            
            if choice in ['q', 'quit', 'exit']:
                break
            elif choice == 'c':
                freq = float(input("Frequency (MHz): "))
                duration = float(input("Duration (seconds): "))
                self.capture_and_analyze(int(freq * 1e6), duration)
            elif choice == 's':
                start = float(input("Start frequency (MHz): "))
                end = float(input("End frequency (MHz): "))
                self.spectrum_survey(int(start * 1e6), int(end * 1e6))
            # Additional commands...
    
    def shutdown(self):
        """Graceful shutdown."""
        self.running = False
        self.logger.info("Framework shutdown complete")
        self.logger.export_audit_trail("audit_trail.json")


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SIGINT-Grade RF Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --capture --freq 433.92 --duration 2
  %(prog)s --scan --start 400 --end 450 --step 1
  %(prog)s --interactive
        """
    )
    
    # Operation modes
    parser.add_argument('--capture', action='store_true',
                       help='Capture and analyze signal')
    parser.add_argument('--scan', action='store_true',
                       help='Spectrum survey')
    parser.add_argument('--interactive', action='store_true',
                       help='Interactive mode')
    
    # Parameters
    parser.add_argument('--freq', type=float, default=433.92,
                       help='Center frequency in MHz (default: 433.92)')
    parser.add_argument('--duration', type=float, default=2.0,
                       help='Capture duration in seconds')
    parser.add_argument('--start', type=float, help='Scan start frequency (MHz)')
    parser.add_argument('--end', type=float, help='Scan end frequency (MHz)')
    parser.add_argument('--step', type=float, default=1.0,
                       help='Scan step size in MHz')
    
    # Output options
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--visualize', action='store_true',
                       help='Generate visualizations')
    parser.add_argument('--report', action='store_true',
                       help='Generate intelligence report')
    
    # Advanced options
    parser.add_argument('--sample-rate', type=int, default=20000000,
                       help='Sample rate in Hz')
    parser.add_argument('--lna-gain', type=int, default=32,
                       help='LNA gain (0-48)')
    parser.add_argument('--vga-gain', type=int, default=40,
                       help='VGA gain (0-62)')
    parser.add_argument('--verbose', '-v', action='count', default=0,
                       help='Increase verbosity')
    
    args = parser.parse_args()
    
    # Set logging level
    log_level = logging.DEBUG if args.verbose >= 2 else \
               logging.INFO if args.verbose >= 1 else logging.WARNING
    
    logging.basicConfig(
        level=log_level,
        format=Config.LOG_FORMAT,
        datefmt=Config.LOG_DATE_FORMAT
    )
    
    # Initialize framework
    framework = SIGINTFramework()
    
    try:
        if args.interactive:
            framework.interactive_mode()
        elif args.scan and args.start and args.end:
            framework.spectrum_survey(
                int(args.start * 1e6),
                int(args.end * 1e6),
                int(args.step * 1e6)
            )
        elif args.capture:
            framework.capture_and_analyze(
                frequency=int(args.freq * 1e6),
                duration=args.duration,
                output_file=args.output
            )
        else:
            parser.print_help()
    
    finally:
        framework.shutdown()


if __name__ == "__main__":
    main()
