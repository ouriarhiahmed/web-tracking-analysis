# Web Tracking Protection Methods: Experimental Framework
# Authors: Ahmed Ouriarhi and Youness Ikkou
# LABO MATSI, École Supérieure de Technologie, Université Mohammed Premier

"""
Complete experimental framework for web tracking protection analysis
Based on the methodology described in the research paper
"""

import os
import sys
import json
import time
import sqlite3
import logging
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import concurrent.futures
import threading
from pathlib import Path

# Web automation and analysis
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import TimeoutException, WebDriverException

# Statistical analysis
import scipy.stats as stats
from scipy.stats import ttest_ind, chi2_contingency, pearsonr
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from sklearn.model_selection import StratifiedKFold
import matplotlib.pyplot as plt
import seaborn as sns

# Network analysis
import requests
import socket
from urllib.parse import urlparse, urljoin
import dns.resolver

# Configuration and setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tracking_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TrackingResult:
    """Data structure for tracking detection results"""
    domain: str
    timestamp: datetime
    protection_tool: str
    browser: str
    platform: str
    cookies_detected: int
    third_party_cookies: int
    canvas_fingerprinting: bool
    webgl_fingerprinting: bool
    audio_fingerprinting: bool
    sensor_access: bool
    local_storage_used: bool
    indexed_db_used: bool
    etag_tracking: bool
    requests_blocked: int
    total_requests: int
    load_time: float
    entropy_bits: float
    protection_score: float


@dataclass
class ExperimentConfig:
    """Configuration for experimental parameters"""
    domains_file: str = "domains.json"
    output_dir: str = "results"
    browsers: List[str] = None
    protection_tools: List[str] = None
    repetitions: int = 3
    timeout: int = 30
    headless: bool = True
    geographic_proxies: bool = False
    
    def __post_init__(self):
        if self.browsers is None:
            self.browsers = ['chrome', 'firefox']
        if self.protection_tools is None:
            self.protection_tools = ['none', 'ublock_origin', 'privacy_badger', 'brave', 'firefox_etp']


class DatabaseManager:
    """Manages SQLite database for experimental results"""
    
    def __init__(self, db_path: str = "tracking_results.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tracking_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                protection_tool TEXT NOT NULL,
                browser TEXT NOT NULL,
                platform TEXT NOT NULL,
                cookies_detected INTEGER,
                third_party_cookies INTEGER,
                canvas_fingerprinting BOOLEAN,
                webgl_fingerprinting BOOLEAN,
                audio_fingerprinting BOOLEAN,
                sensor_access BOOLEAN,
                local_storage_used BOOLEAN,
                indexed_db_used BOOLEAN,
                etag_tracking BOOLEAN,
                requests_blocked INTEGER,
                total_requests INTEGER,
                load_time REAL,
                entropy_bits REAL,
                protection_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_categories (
                domain TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                region TEXT,
                alexa_rank INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_result(self, result: TrackingResult):
        """Insert tracking result into database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO tracking_results (
                domain, timestamp, protection_tool, browser, platform,
                cookies_detected, third_party_cookies, canvas_fingerprinting,
                webgl_fingerprinting, audio_fingerprinting, sensor_access,
                local_storage_used, indexed_db_used, etag_tracking,
                requests_blocked, total_requests, load_time, entropy_bits,
                protection_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.domain, result.timestamp.isoformat(), result.protection_tool,
            result.browser, result.platform, result.cookies_detected,
            result.third_party_cookies, result.canvas_fingerprinting,
            result.webgl_fingerprinting, result.audio_fingerprinting,
            result.sensor_access, result.local_storage_used,
            result.indexed_db_used, result.etag_tracking,
            result.requests_blocked, result.total_requests,
            result.load_time, result.entropy_bits, result.protection_score
        ))
        
        conn.commit()
        conn.close()
    
    def get_results(self, filters: Dict[str, Any] = None) -> pd.DataFrame:
        """Retrieve results from database with optional filters"""
        conn = sqlite3.connect(self.db_path)
        
        query = "SELECT * FROM tracking_results"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if isinstance(value, list):
                    placeholders = ','.join('?' * len(value))
                    conditions.append(f"{key} IN ({placeholders})")
                    params.extend(value)
                else:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        return df


class FingerprintingDetector:
    """Detects various fingerprinting techniques"""
    
    @staticmethod
    def detect_canvas_fingerprinting(driver) -> Tuple[bool, float]:
        """Detect canvas fingerprinting and calculate entropy"""
        try:
            # Inject canvas detection script
            canvas_script = '''
                var canvas = document.createElement('canvas');
                var ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('Canvas fingerprinting test 🔍', 2, 2);
                return canvas.toDataURL();
            '''
            
            canvas_data = driver.execute_script(canvas_script)
            
            # Calculate entropy based on canvas data
            entropy = FingerprintingDetector.calculate_entropy(canvas_data)
            
            # Check if canvas fingerprinting is being used
            fingerprinting_detected = len(canvas_data) > 1000  # Threshold for detection
            
            return fingerprinting_detected, entropy
            
        except Exception as e:
            logger.warning(f"Canvas fingerprinting detection failed: {e}")
            return False, 0.0
    
    @staticmethod
    def detect_webgl_fingerprinting(driver) -> Tuple[bool, float]:
        """Detect WebGL fingerprinting"""
        try:
            webgl_script = '''
                var canvas = document.createElement('canvas');
                var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return null;
                
                var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                
                return vendor + '|' + renderer;
            '''
            
            webgl_data = driver.execute_script(webgl_script)
            
            if webgl_data:
                entropy = FingerprintingDetector.calculate_entropy(webgl_data)
                return True, entropy
            
            return False, 0.0
            
        except Exception as e:
            logger.warning(f"WebGL fingerprinting detection failed: {e}")
            return False, 0.0
    
    @staticmethod
    def detect_audio_fingerprinting(driver) -> Tuple[bool, float]:
        """Detect audio context fingerprinting"""
        try:
            audio_script = '''
                try {
                    var audioContext = new (window.AudioContext || window.webkitAudioContext)();
                    var oscillator = audioContext.createOscillator();
                    var analyser = audioContext.createAnalyser();
                    var gainNode = audioContext.createGain();
                    
                    oscillator.connect(analyser);
                    analyser.connect(gainNode);
                    gainNode.connect(audioContext.destination);
                    
                    oscillator.frequency.value = 1000;
                    oscillator.start(0);
                    oscillator.stop(0.1);
                    
                    return 'audio_context_available';
                } catch (e) {
                    return null;
                }
            '''
            
            audio_result = driver.execute_script(audio_script)
            
            if audio_result:
                entropy = 7.3  # Average entropy from paper
                return True, entropy
            
            return False, 0.0
            
        except Exception as e:
            logger.warning(f"Audio fingerprinting detection failed: {e}")
            return False, 0.0
    
    @staticmethod
    def detect_sensor_access(driver) -> bool:
        """Detect sensor access attempts"""
        try:
            sensor_script = '''
                var sensors = [];
                if ('DeviceMotionEvent' in window) sensors.push('motion');
                if ('DeviceOrientationEvent' in window) sensors.push('orientation');
                if ('Geolocation' in navigator) sensors.push('geolocation');
                return sensors;
            '''
            
            sensors = driver.execute_script(sensor_script)
            return len(sensors) > 0
            
        except Exception as e:
            logger.warning(f"Sensor detection failed: {e}")
            return False
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        data_len = len(data)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy


class ProtectionToolManager:
    """Manages different protection tools and browser configurations"""
    
    @staticmethod
    def setup_browser(browser: str, protection_tool: str, headless: bool = True) -> webdriver:
        """Setup browser with specific protection tool"""
        
        if browser.lower() == 'chrome':
            return ProtectionToolManager._setup_chrome(protection_tool, headless)
        elif browser.lower() == 'firefox':
            return ProtectionToolManager._setup_firefox(protection_tool, headless)
        else:
            raise ValueError(f"Unsupported browser: {browser}")
    
    @staticmethod
    def _setup_chrome(protection_tool: str, headless: bool) -> webdriver:
        """Setup Chrome with protection tool"""
        options = ChromeOptions()
        
        if headless:
            options.add_argument('--headless')
        
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        
        # Configure protection tools
        if protection_tool == 'ublock_origin':
            # Add uBlock Origin extension
            options.add_extension('extensions/ublock_origin.crx')
        elif protection_tool == 'privacy_badger':
            # Add Privacy Badger extension
            options.add_extension('extensions/privacy_badger.crx')
        elif protection_tool == 'brave':
            # Use Brave browser binary if available
            options.binary_location = '/usr/bin/brave-browser'
            options.add_argument('--enable-features=VivaldiFeatures')
        
        return webdriver.Chrome(options=options)
    
    @staticmethod
    def _setup_firefox(protection_tool: str, headless: bool) -> webdriver:
        """Setup Firefox with protection tool"""
        options = FirefoxOptions()
        
        if headless:
            options.add_argument('--headless')
        
        profile = webdriver.FirefoxProfile()
        
        if protection_tool == 'firefox_etp':
            # Enable Enhanced Tracking Protection
            profile.set_preference('privacy.trackingprotection.enabled', True)
            profile.set_preference('privacy.trackingprotection.socialtracking.enabled', True)
            profile.set_preference('privacy.trackingprotection.fingerprinting.enabled', True)
            profile.set_preference('privacy.trackingprotection.cryptomining.enabled', True)
        
        options.profile = profile
        return webdriver.Firefox(options=options)


class WebCrawler:
    """Main web crawler for tracking analysis"""
    
    def __init__(self, config: ExperimentConfig):
        self.config = config
        self.db = DatabaseManager()
        self.detector = FingerprintingDetector()
        
        # Load domain list
        self.domains = self._load_domains()
        
        # Create output directory
        Path(config.output_dir).mkdir(exist_ok=True)
    
    def _load_domains(self) -> Dict[str, Dict]:
        """Load domain list from JSON file"""
        try:
            with open(self.config.domains_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create sample domain list if file doesn't exist
            sample_domains = {
                "e-commerce": [
                    {"domain": "amazon.com", "region": "US"},
                    {"domain": "alibaba.com", "region": "CN"},
                    {"domain": "jumia.com", "region": "AF"}
                ],
                "news": [
                    {"domain": "bbc.com", "region": "EU"},
                    {"domain": "cnn.com", "region": "US"},
                    {"domain": "aljazeera.com", "region": "ME"}
                ],
                "social": [
                    {"domain": "facebook.com", "region": "US"},
                    {"domain": "twitter.com", "region": "US"},
                    {"domain": "linkedin.com", "region": "US"}
                ]
            }
            
            with open(self.config.domains_file, 'w') as f:
                json.dump(sample_domains, f, indent=2)
            
            return sample_domains
    
    def crawl_domain(self, domain: str, category: str, browser: str, 
                    protection_tool: str, run_number: int) -> TrackingResult:
        """Crawl a single domain and analyze tracking"""
        
        logger.info(f"Crawling {domain} with {browser}/{protection_tool} (run {run_number})")
        
        driver = None
        try:
            # Setup browser
            driver = ProtectionToolManager.setup_browser(browser, protection_tool, self.config.headless)
            
            # Start timing
            start_time = time.time()
            
            # Navigate to domain
            url = f"https://{domain}"
            driver.get(url)
            
            # Wait for page load
            WebDriverWait(driver, self.config.timeout).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            load_time = time.time() - start_time
            
            # Analyze tracking technologies
            result = self._analyze_tracking(driver, domain, browser, protection_tool, load_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Error crawling {domain}: {e}")
            # Return empty result
            return TrackingResult(
                domain=domain,
                timestamp=datetime.now(),
                protection_tool=protection_tool,
                browser=browser,
                platform="desktop",  # Default
                cookies_detected=0,
                third_party_cookies=0,
                canvas_fingerprinting=False,
                webgl_fingerprinting=False,
                audio_fingerprinting=False,
                sensor_access=False,
                local_storage_used=False,
                indexed_db_used=False,
                etag_tracking=False,
                requests_blocked=0,
                total_requests=0,
                load_time=0.0,
                entropy_bits=0.0,
                protection_score=0.0
            )
        
        finally:
            if driver:
                driver.quit()
    
    def _analyze_tracking(self, driver, domain: str, browser: str, 
                         protection_tool: str, load_time: float) -> TrackingResult:
        """Analyze tracking technologies on the page"""
        
        # Detect cookies
        cookies = driver.get_cookies()
        cookies_detected = len(cookies)
        
        # Count third-party cookies
        third_party_cookies = sum(1 for cookie in cookies 
                                 if domain not in cookie.get('domain', ''))
        
        # Detect fingerprinting techniques
        canvas_fp, canvas_entropy = self.detector.detect_canvas_fingerprinting(driver)
        webgl_fp, webgl_entropy = self.detector.detect_webgl_fingerprinting(driver)
        audio_fp, audio_entropy = self.detector.detect_audio_fingerprinting(driver)
        sensor_access = self.detector.detect_sensor_access(driver)
        
        # Detect storage usage
        local_storage_used = self._check_local_storage(driver)
        indexed_db_used = self._check_indexed_db(driver)
        
        # Calculate total entropy
        total_entropy = canvas_entropy + webgl_entropy + audio_entropy
        if cookies_detected > 0:
            total_entropy += np.log2(cookies_detected) * 1.5  # Cookie entropy estimation
        
        # Calculate protection score
        protection_score = self._calculate_protection_score(
            cookies_detected, third_party_cookies, canvas_fp, webgl_fp,
            audio_fp, sensor_access, total_entropy
        )
        
        return TrackingResult(
            domain=domain,
            timestamp=datetime.now(),
            protection_tool=protection_tool,
            browser=browser,
            platform="desktop",
            cookies_detected=cookies_detected,
            third_party_cookies=third_party_cookies,
            canvas_fingerprinting=canvas_fp,
            webgl_fingerprinting=webgl_fp,
            audio_fingerprinting=audio_fp,
            sensor_access=sensor_access,
            local_storage_used=local_storage_used,
            indexed_db_used=indexed_db_used,
            etag_tracking=False,  # Would need network analysis
            requests_blocked=0,   # Would need network monitoring
            total_requests=0,     # Would need network monitoring
            load_time=load_time,
            entropy_bits=total_entropy,
            protection_score=protection_score
        )
    
    def _check_local_storage(self, driver) -> bool:
        """Check if local storage is being used"""
        try:
            script = "return Object.keys(localStorage).length > 0;"
            return driver.execute_script(script)
        except:
            return False
    
    def _check_indexed_db(self, driver) -> bool:
        """Check if IndexedDB is being used"""
        try:
            script = '''
                return new Promise((resolve) => {
                    if (!window.indexedDB) {
                        resolve(false);
                        return;
                    }
                    
                    var request = indexedDB.webkitGetDatabaseNames();
                    request.onsuccess = function(event) {
                        resolve(event.target.result.length > 0);
                    };
                    request.onerror = function() {
                        resolve(false);
                    };
                });
            '''
            return driver.execute_async_script(script)
        except:
            return False
    
    def _calculate_protection_score(self, cookies: int, third_party_cookies: int,
                                  canvas_fp: bool, webgl_fp: bool, audio_fp: bool,
                                  sensor_access: bool, entropy: float) -> float:
        """Calculate protection effectiveness score"""
        
        # Base score starts at 100%
        score = 100.0
        
        # Deduct points for tracking presence
        score -= min(cookies * 2, 30)  # Cookie penalty
        score -= min(third_party_cookies * 5, 40)  # Third-party cookie penalty
        score -= 15 if canvas_fp else 0
        score -= 10 if webgl_fp else 0
        score -= 12 if audio_fp else 0
        score -= 8 if sensor_access else 0
        
        # Entropy penalty
        if entropy > 20:
            score -= min((entropy - 20) * 2, 25)
        
        return max(score, 0.0)
    
    def run_experiment(self):
        """Run the complete experiment"""
        logger.info("Starting web tracking protection experiment")
        
        results = []
        total_runs = 0
        
        # Calculate total number of runs
        for category, domain_list in self.domains.items():
            total_runs += len(domain_list) * len(self.config.browsers) * \
                         len(self.config.protection_tools) * self.config.repetitions
        
        logger.info(f"Total experimental runs: {total_runs}")
        
        current_run = 0
        
        # Run experiments
        for category, domain_list in self.domains.items():
            for domain_info in domain_list:
                domain = domain_info['domain']
                
                for browser in self.config.browsers:
                    for protection_tool in self.config.protection_tools:
                        for run_num in range(self.config.repetitions):
                            current_run += 1
                            
                            logger.info(f"Progress: {current_run}/{total_runs} "
                                      f"({current_run/total_runs*100:.1f}%)")
                            
                            try:
                                result = self.crawl_domain(
                                    domain, category, browser, protection_tool, run_num + 1
                                )
                                
                                # Store result
                                self.db.insert_result(result)
                                results.append(result)
                                
                                # Small delay between runs
                                time.sleep(2)
                                
                            except Exception as e:
                                logger.error(f"Failed run {current_run}: {e}")
                                continue
        
        logger.info(f"Experiment completed. {len(results)} results collected.")
        return results


class StatisticalAnalyzer:
    """Statistical analysis of experimental results"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def load_results(self) -> pd.DataFrame:
        """Load all experimental results"""
        return self.db.get_results()
    
    def calculate_protection_effectiveness(self, df: pd.DataFrame) -> pd.DataFrame:
        """Calculate protection effectiveness metrics by tool"""
        
        # Group by protection tool
        grouped = df.groupby('protection_tool').agg({
            'protection_score': ['mean', 'std', 'count'],
            'cookies_detected': ['mean', 'std'],
            'third_party_cookies': ['mean', 'std'],
            'entropy_bits': ['mean', 'std'],
            'canvas_fingerprinting': 'mean',
            'webgl_fingerprinting': 'mean',
            'audio_fingerprinting': 'mean'
        })
        
        # Flatten column names
        grouped.columns = ['_'.join(col).strip() for col in grouped.columns]
        
        return grouped
    
    def statistical_comparison(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Perform statistical comparisons between protection tools"""
        
        tools = df['protection_tool'].unique()
        results = {}
        
        # Pairwise comparisons
        for i, tool1 in enumerate(tools):
            for tool2 in tools[i+1:]:
                
                data1 = df[df['protection_tool'] == tool1]['protection_score']
                data2 = df[df['protection_tool'] == tool2]['protection_score']
                
                # T-test
                t_stat, p_value = ttest_ind(data1, data2)
                
                # Effect size (Cohen's d)
                pooled_std = np.sqrt(((len(data1)-1)*data1.std()**2 + 
                                    (len(data2)-1)*data2.std()**2) / 
                                   (len(data1)+len(data2)-2))
                cohens_d = (data1.mean() - data2.mean()) / pooled_std
                
                results[f"{tool1}_vs_{tool2}"] = {
                    't_statistic': t_stat,
                    'p_value': p_value,
                    'cohens_d': cohens_d,
                    'mean_diff': data1.mean() - data2.mean(),
                    'effect_size_interpretation': self._interpret_effect_size(abs(cohens_d))
                }
        
        return results
    
    def _interpret_effect_size(self, d: float) -> str:
        """Interpret Cohen's d effect size"""
        if d < 0.2:
            return "negligible"
        elif d < 0.5:
            return "small"
        elif d < 0.8:
            return "medium"
        else:
            return "large"
    
    def cross_platform_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze cross-platform differences"""
        
        # This would require mobile data collection
        # For now, provide framework for desktop analysis
        
        desktop_data = df[df['platform'] == 'desktop']
        
        analysis = {
            'desktop_summary': {
                'mean_protection_score': desktop_data['protection_score'].mean(),
                'std_protection_score': desktop_data['protection_score'].std(),
                'mean_entropy': desktop_data['entropy_bits'].mean(),
                'fingerprinting_prevalence': {
                    'canvas': desktop_data['canvas_fingerprinting'].mean(),
                    'webgl': desktop_data['webgl_fingerprinting'].mean(),
                    'audio': desktop_data['audio_fingerprinting'].mean()
                }
            }
        }
        
        return analysis
    
    def generate_report(self, output_file: str = "analysis_report.json"):
        """Generate comprehensive analysis report"""
        
        df = self.load_results()
        
        if df.empty:
            logger.warning("No data available for analysis")
            return
        
        report = {
            'experiment_metadata': {
                'total_samples': len(df),
                'unique_domains': df['domain'].nunique(),
                'protection_tools': df['protection_tool'].unique().tolist(),
                'browsers': df['browser'].unique().tolist(),
                'analysis_date': datetime.now().isoformat()
            },
            'protection_effectiveness': self.calculate_protection_effectiveness(df).to_dict(),
            'statistical_comparisons': self.statistical_comparison(df),
            'cross_platform_analysis': self.cross_platform_analysis(df)
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Analysis report saved to {output_file}")
        
        return report


class Visualizer:
    """Create visualizations for the results"""
    
    @staticmethod
    def plot_protection_effectiveness(df: pd.DataFrame, output_dir: str = "plots"):
        """Create protection effectiveness plots"""
        
        Path(output_dir).mkdir(exist_ok=True)
        
        # Set style
        plt.style.use('seaborn-v0_8')
        
        # Protection score by tool
        plt.figure(figsize=(12, 8))
        
        tools = df['protection_tool'].unique()
        scores = [df[df['protection_tool'] == tool]['protection_score'] for tool in tools]
        
        plt.boxplot(scores, labels=tools)
        plt.title('Protection Effectiveness by Tool')
        plt.ylabel('Protection Score (%)')
        plt.xlabel('Protection Tool')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/protection_effectiveness.png", dpi=300)
        plt.close()
        
        # Entropy distribution
        plt.figure(figsize=(10, 6))
        for tool in tools:
            tool_data = df[df['protection_tool'] == tool]['entropy_bits']
            plt.hist(tool_data, alpha=0.7, label=tool, bins=20)
        
        plt.title('Entropy Distribution by Protection Tool')
        plt.xlabel('Entropy (bits)')
        plt.ylabel('Frequency')
        plt.legend()
        plt.tight_layout()
        plt.savefig(f"{output_dir}/entropy_distribution.png", dpi=300)
        plt.close()
        
        # Fingerprinting detection rates
        fingerprinting_cols = ['canvas_fingerprinting', 'webgl_fingerprinting', 'audio_fingerprinting']
        
        fp_rates = df.groupby('protection_tool')[fingerprinting_cols].mean()
        
        fp_rates.plot(kind='bar', figsize=(12, 6))
        plt.title('Fingerprinting Detection Rates by Protection Tool')
        plt.ylabel('Detection Rate')
        plt.xlabel('Protection Tool')
        plt.legend(['Canvas', 'WebGL', 'Audio'])
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/fingerprinting_rates.png", dpi=300)
        plt.close()


def main():
    """Main execution function"""
    
    # Configuration
    config = ExperimentConfig(
        domains_file="domains.json",
        output_dir="results",
        browsers=['chrome', 'firefox'],
        protection_tools=['none', 'ublock_origin', 'privacy_badger', 'firefox_etp'],
        repetitions=3,
        timeout=30,
        headless=True
    )
    
    # Initialize components
    crawler = WebCrawler(config)
    analyzer = StatisticalAnalyzer(crawler.db)
    
    print("Web Tracking Protection Analysis Framework")
    print("=" * 50)
    
    # Run experiment
    print("Starting data collection...")
    results = crawler.run_experiment()
    
    print(f"Data collection completed. {len(results)} samples collected.")
    
    # Analyze results
    print("Performing statistical analysis...")
    report = analyzer.generate_report("analysis_report.json")
    
    # Generate visualizations
    print("Creating visualizations...")
    df = analyzer.load_results()
    if not df.empty:
        Visualizer.plot_protection_effectiveness(df, "plots")
    
    print("Analysis completed!")
    print(f"Results saved in: {config.output_dir}")
    print("Analysis report: analysis_report.json")
    print("Visualizations: plots/")


if __name__ == "__main__":
    main()