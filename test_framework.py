# test_framework.py
"""
Testing framework for the web tracking analysis system
"""

import unittest
import tempfile
import sqlite3
import json
import os
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from web_tracking_analyzer import (
    DatabaseManager, FingerprintingDetector, TrackingResult,
    ExperimentConfig, StatisticalAnalyzer, WebCrawler
)


class TestDatabaseManager(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Set up test database"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db = DatabaseManager(self.temp_db.name)
    
    def tearDown(self):
        """Clean up test database"""
        os.unlink(self.temp_db.name)
    
    def test_database_initialization(self):
        """Test database schema creation"""
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('tracking_results', tables)
        self.assertIn('domain_categories', tables)
        
        conn.close()
    
    def test_insert_and_retrieve_result(self):
        """Test inserting and retrieving tracking results"""
        result = TrackingResult(
            domain="test.com",
            timestamp=datetime.now(),
            protection_tool="ublock_origin",
            browser="chrome",
            platform="desktop",
            cookies_detected=5,
            third_party_cookies=3,
            canvas_fingerprinting=True,
            webgl_fingerprinting=False,
            audio_fingerprinting=True,
            sensor_access=False,
            local_storage_used=True,
            indexed_db_used=False,
            etag_tracking=False,
            requests_blocked=10,
            total_requests=50,
            load_time=2.5,
            entropy_bits=15.2,
            protection_score=85.5
        )
        
        # Insert result
        self.db.insert_result(result)
        
        # Retrieve results
        df = self.db.get_results()
        
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]['domain'], "test.com")
        self.assertEqual(df.iloc[0]['protection_tool'], "ublock_origin")
        self.assertEqual(df.iloc[0]['cookies_detected'], 5)


class TestFingerprintingDetector(unittest.TestCase):
    """Test fingerprinting detection methods"""
    
    def setUp(self):
        """Set up mock driver"""
        self.mock_driver = Mock()
    
    def test_calculate_entropy(self):
        """Test entropy calculation"""
        # Test with known data
        test_data = "abcdef"
        entropy = FingerprintingDetector.calculate_entropy(test_data)
        
        # Should be close to log2(6) for uniform distribution
        expected_entropy = 2.585  # log2(6)
        self.assertAlmostEqual(entropy, expected_entropy, places=2)
    
    def test_canvas_fingerprinting_detection(self):
        """Test canvas fingerprinting detection"""
        # Mock canvas data response
        self.mock_driver.execute_script.return_value = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
        
        detected, entropy = FingerprintingDetector.detect_canvas_fingerprinting(self.mock_driver)
        
        self.assertTrue(detected)  # Should detect fingerprinting with long data
        self.assertGreater(entropy, 0)
    
    def test_webgl_fingerprinting_detection(self):
        """Test WebGL fingerprinting detection"""
        self.mock_driver.execute_script.return_value = "Intel Inc.|Intel HD Graphics"
        
        detected, entropy = FingerprintingDetector.detect_webgl_fingerprinting(self.mock_driver)
        
        self.assertTrue(detected)
        self.assertGreater(entropy, 0)


class TestStatisticalAnalyzer(unittest.TestCase):
    """Test statistical analysis functions"""
    
    def setUp(self):
        """Set up test data"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db = DatabaseManager(self.temp_db.name)
        self.analyzer = StatisticalAnalyzer(self.db)
        
        # Insert test data
        self._insert_test_data()
    
    def tearDown(self):
        """Clean up"""
        os.unlink(self.temp_db.name)
    
    def _insert_test_data(self):
        """Insert sample test data"""
        tools = ['none', 'ublock_origin', 'privacy_badger']
        scores = [50, 90, 70]  # Different effectiveness levels
        
        for i, (tool, score) in enumerate(zip(tools, scores)):
            for j in range(10):  # 10 samples per tool
                result = TrackingResult(
                    domain=f"test{j}.com",
                    timestamp=datetime.now(),
                    protection_tool=tool,
                    browser="chrome",
                    platform="desktop",
                    cookies_detected=10 - (i * 3),
                    third_party_cookies=5 - (i * 2),
                    canvas_fingerprinting=i == 0,  # Only for 'none'
                    webgl_fingerprinting=i == 0,
                    audio_fingerprinting=i == 0,
                    sensor_access=i == 0,
                    local_storage_used=True,
                    indexed_db_used=False,
                    etag_tracking=False,
                    requests_blocked=i * 20,
                    total_requests=50,
                    load_time=2.0,
                    entropy_bits=20 - (i * 5),
                    protection_score=score + (j - 5)  # Add some variation
                )
                self.db.insert_result(result)
    
    def test_load_results(self):
        """Test loading results from database"""
        df = self.analyzer.load_results()
        
        self.assertEqual(len(df), 30)  # 3 tools × 10 samples
        self.assertEqual(len(df['protection_tool'].unique()), 3)
    
    def test_protection_effectiveness_calculation(self):
        """Test protection effectiveness metrics"""
        df = self.analyzer.load_results()
        effectiveness = self.analyzer.calculate_protection_effectiveness(df)
        
        # Check that uBlock Origin has higher scores than none
        ublock_mean = effectiveness.loc['ublock_origin', 'protection_score_mean']
        none_mean = effectiveness.loc['none', 'protection_score_mean']
        
        self.assertGreater(ublock_mean, none_mean)
    
    def test_statistical_comparison(self):
        """Test statistical comparisons between tools"""
        df = self.analyzer.load_results()
        comparisons = self.analyzer.statistical_comparison(df)
        
        # Should have comparisons between all tool pairs
        self.assertIn('none_vs_ublock_origin', comparisons)
        self.assertIn('none_vs_privacy_badger', comparisons)
        
        # uBlock Origin vs none should show significant difference
        comparison = comparisons['none_vs_ublock_origin']
        self.assertLess(comparison['p_value'], 0.05)  # Significant difference
        self.assertGreater(abs(comparison['cohens_d']), 0.8)  # Large effect size


class TestExperimentConfig(unittest.TestCase):
    """Test experiment configuration"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ExperimentConfig()
        
        self.assertEqual(config.domains_file, "domains.json")
        self.assertEqual(config.repetitions, 3)
        self.assertIn('chrome', config.browsers)
        self.assertIn('ublock_origin', config.protection_tools)
    
    def test_custom_config(self):
        """Test custom configuration"""
        config = ExperimentConfig(
            repetitions=5,
            browsers=['firefox'],
            protection_tools=['privacy_badger']
        )
        
        self.assertEqual(config.repetitions, 5)
        self.assertEqual(config.browsers, ['firefox'])
        self.assertEqual(config.protection_tools, ['privacy_badger'])


class TestWebCrawler(unittest.TestCase):
    """Test web crawler functionality"""
    
    def setUp(self):
        """Set up test crawler"""
        # Create temporary domain file
        self.temp_domains = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        test_domains = {
            "test": [
                {"domain": "example.com", "region": "US"}
            ]
        }
        json.dump(test_domains, self.temp_domains)
        self.temp_domains.close()
        
        # Create config with test domain file
        self.config = ExperimentConfig(
            domains_file=self.temp_domains.name,
            repetitions=1,
            browsers=['chrome'],
            protection_tools=['none']
        )
        
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        
    def tearDown(self):
        """Clean up"""
        os.unlink(self.temp_domains.name)
        os.unlink(self.temp_db.name)
    
    def test_load_domains(self):
        """Test domain loading"""
        crawler = WebCrawler(self.config)
        
        self.assertIn("test", crawler.domains)
        self.assertEqual(len(crawler.domains["test"]), 1)
        self.assertEqual(crawler.domains["test"][0]["domain"], "example.com")
    
    @patch('web_tracking_analyzer.ProtectionToolManager.setup_browser')
    def test_crawl_domain_mock(self, mock_setup_browser):
        """Test domain crawling with mocked browser"""
        # Mock browser behavior
        mock_driver = Mock()
        mock_driver.get_cookies.return_value = [
            {'domain': 'example.com', 'name': 'test_cookie'}
        ]
        mock_driver.execute_script.side_effect = [
            "data:image/png;base64,test",  # Canvas
            None,  # WebGL
            None,  # Audio
            [],   # Sensors
            False,  # LocalStorage
            False   # IndexedDB
        ]
        
        mock_setup_browser.return_value = mock_driver
        
        # Override database path
        self.config.domains_file = self.temp_domains.name
        crawler = WebCrawler(self.config)
        crawler.db = DatabaseManager(self.temp_db.name)
        
        result = crawler.crawl_domain("example.com", "test", "chrome", "none", 1)
        
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.browser, "chrome")
        self.assertEqual(result.protection_tool, "none")
        self.assertGreaterEqual(result.cookies_detected, 0)


def run_performance_test():
    """Run performance tests for the framework"""
    import time
    
    print("Running performance tests...")
    
    # Test database operations
    start_time = time.time()
    
    temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    db = DatabaseManager(temp_db.name)
    
    # Insert 1000 sample results
    for i in range(1000):
        result = TrackingResult(
            domain=f"test{i}.com",
            timestamp=datetime.now(),
            protection_tool="test_tool",
            browser="chrome",
            platform="desktop",
            cookies_detected=i % 10,
            third_party_cookies=i % 5,
            canvas_fingerprinting=i % 2 == 0,
            webgl_fingerprinting=i % 3 == 0,
            audio_fingerprinting=i % 4 == 0,
            sensor_access=i % 5 == 0,
            local_storage_used=True,
            indexed_db_used=False,
            etag_tracking=False,
            requests_blocked=i,
            total_requests=i + 50,
            load_time=2.0 + (i % 10) * 0.1,
            entropy_bits=10 + (i % 20),
            protection_score=50 + (i % 50)
        )
        db.insert_result(result)
    
    insert_time = time.time() - start_time
    print(f"Inserted 1000 records in {insert_time:.2f} seconds")
    
    # Test retrieval
    start_time = time.time()
    df = db.get_results()
    retrieval_time = time.time() - start_time
    print(f"Retrieved {len(df)} records in {retrieval_time:.2f} seconds")
    
    # Test analysis
    start_time = time.time()
    analyzer = StatisticalAnalyzer(db)
    effectiveness = analyzer.calculate_protection_effectiveness(df)
    analysis_time = time.time() - start_time
    print(f"Analyzed data in {analysis_time:.2f} seconds")
    
    # Cleanup
    os.unlink(temp_db.name)
    
    print("Performance tests completed.")


if __name__ == "__main__":
    # Run unit tests
    print("Running unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=2)
    
    # Run performance tests
    print("\n" + "="*50)
    run_performance_test()


# validation_scripts.py
"""
Validation scripts for experimental methodology
"""

import pandas as pd
import numpy as np
from scipy import stats
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple


class ExperimentValidator:
    """Validates experimental design and results"""
    
    @staticmethod
    def validate_sample_size(effect_size: float = 0.5, alpha: float = 0.05, 
                           power: float = 0.8) -> int:
        """Calculate required sample size for given parameters"""
        
        # Using Cohen's formula for two-sample t-test
        z_alpha = stats.norm.ppf(1 - alpha/2)
        z_beta = stats.norm.ppf(power)
        
        n = 2 * ((z_alpha + z_beta) / effect_size) ** 2
        
        return int(np.ceil(n))
    
    @staticmethod
    def check_normality(data: pd.Series, alpha: float = 0.05) -> Dict[str, float]:
        """Test normality assumptions"""
        
        # Shapiro-Wilk test
        shapiro_stat, shapiro_p = stats.shapiro(data)
        
        # Kolmogorov-Smirnov test
        ks_stat, ks_p = stats.kstest(data, 'norm', args=(data.mean(), data.std()))
        
        return {
            'shapiro_statistic': shapiro_stat,
            'shapiro_p_value': shapiro_p,
            'shapiro_normal': shapiro_p > alpha,
            'ks_statistic': ks_stat,
            'ks_p_value': ks_p,
            'ks_normal': ks_p > alpha
        }
    
    @staticmethod
    def validate_randomization(df: pd.DataFrame) -> Dict[str, Any]:
        """Check randomization quality"""
        
        # Check temporal distribution
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day
        
        # Chi-square test for uniform distribution across hours
        hour_counts = df['hour'].value_counts()
        chi2_hour, p_hour = stats.chisquare(hour_counts)
        
        # Check balance across protection tools
        tool_counts = df['protection_tool'].value_counts()
        chi2_tools, p_tools = stats.chisquare(tool_counts)
        
        return {
            'temporal_randomization': {
                'hour_chi2': chi2_hour,
                'hour_p_value': p_hour,
                'balanced': p_hour > 0.05
            },
            'tool_balance': {
                'tool_chi2': chi2_tools,
                'tool_p_value': p_tools,
                'balanced': p_tools > 0.05
            }
        }
    
    @staticmethod
    def power_analysis_post_hoc(group1: pd.Series, group2: pd.Series) -> Dict[str, float]:
        """Post-hoc power analysis"""
        
        # Calculate effect size
        pooled_std = np.sqrt(((len(group1)-1)*group1.std()**2 + 
                             (len(group2)-1)*group2.std()**2) / 
                            (len(group1)+len(group2)-2))
        
        cohens_d = abs(group1.mean() - group2.mean()) / pooled_std
        
        # Calculate achieved power
        n1, n2 = len(group1), len(group2)
        n_harmonic = 2 * n1 * n2 / (n1 + n2)
        
        # Power analysis for pairwise comparisons
    tools = df['protection_tool'].unique()
    if len(tools) >= 2:
        tool1_data = df[df['protection_tool'] == tools[0]]['protection_score']
        tool2_data = df[df['protection_tool'] == tools[1]]['protection_score']
        validation_report['power_analysis'] = validator.power_analysis_post_hoc(tool1_data, tool2_data)
    
    # Reproducibility checks
    validation_report['reproducibility']['cv_stability'] = repro_checker.cross_validation_stability(df)
    
    # Bootstrap CIs for main effect
    main_scores = df['protection_score']
    validation_report['reproducibility']['bootstrap_ci'] = repro_checker.bootstrap_confidence_intervals(main_scores)
    
    return validation_report


# entropy_calculator.py
"""
Entropy calculation utilities based on information theory
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple
import math


class EntropyCalculator:
    """Calculate entropy for various fingerprinting vectors"""
    
    @staticmethod
    def shannon_entropy(data: List[str]) -> float:
        """Calculate Shannon entropy for categorical data"""
        if not data:
            return 0.0
        
        # Count frequencies
        counts = {}
        for item in data:
            counts[item] = counts.get(item, 0) + 1
        
        # Calculate probabilities and entropy
        total = len(data)
        entropy = 0.0
        
        for count in counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def canvas_entropy(canvas_data: str) -> float:
        """Calculate entropy for canvas fingerprinting data"""
        if not canvas_data:
            return 0.0
        
        # Convert to character frequency distribution
        char_counts = {}
        for char in canvas_data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        total_chars = len(canvas_data)
        entropy = 0.0
        
        for count in char_counts.values():
            if count > 0:
                probability = count / total_chars
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def webgl_entropy(vendor: str, renderer: str) -> float:
        """Calculate entropy for WebGL fingerprinting"""
        # Combine vendor and renderer info
        combined = f"{vendor}|{renderer}"
        
        # Estimate entropy based on uniqueness
        # This is a simplified model - in practice, you'd need
        # a database of known vendor/renderer combinations
        base_entropy = 9.2  # From paper: 9.2 ± 1.2 bits
        
        # Adjust based on string characteristics
        if len(combined) > 50:
            base_entropy += 1.0
        if "intel" in combined.lower():
            base_entropy -= 0.5  # More common
        if "nvidia" in combined.lower():
            base_entropy += 0.3  # Less common in some contexts
        
        return max(base_entropy, 0.0)
    
    @staticmethod
    def audio_entropy() -> float:
        """Calculate entropy for audio fingerprinting"""
        # From paper: 7.3 ± 0.9 bits
        # Add some randomness to simulate measurement variation
        return 7.3 + np.random.normal(0, 0.9)
    
    @staticmethod
    def sensor_entropy(sensor_types: List[str]) -> float:
        """Calculate entropy for sensor-based fingerprinting"""
        # From paper: 5.8 ± 1.1 bits
        base_entropy = 5.8
        
        # Adjust based on available sensors
        entropy_per_sensor = {
            'accelerometer': 2.1,
            'gyroscope': 1.8,
            'magnetometer': 1.5,
            'ambient_light': 1.2,
            'proximity': 0.8
        }
        
        total_entropy = 0.0
        for sensor in sensor_types:
            total_entropy += entropy_per_sensor.get(sensor, 1.0)
        
        return min(total_entropy, base_entropy + 2.0)  # Cap at reasonable value
    
    @staticmethod
    def combined_entropy(individual_entropies: Dict[str, float], 
                        mutual_info: Dict[Tuple[str, str], float] = None) -> float:
        """
        Calculate combined entropy accounting for mutual information
        Based on equation from paper: H_combined = sum(H_i) - sum(I_ij)
        """
        if not individual_entropies:
            return 0.0
        
        # Sum individual entropies
        total_entropy = sum(individual_entropies.values())
        
        # Subtract mutual information if provided
        if mutual_info:
            total_mutual_info = sum(mutual_info.values())
            total_entropy -= total_mutual_info
        else:
            # Use default mutual information estimates from paper
            # "empirically measured at 2.1-4.3 bits for related features"
            entropy_keys = list(individual_entropies.keys())
            estimated_mutual_info = 0.0
            
            for i, key1 in enumerate(entropy_keys):
                for key2 in entropy_keys[i+1:]:
                    # Estimate mutual information between related features
                    if _are_related_features(key1, key2):
                        estimated_mutual_info += np.random.uniform(2.1, 4.3)
            
            total_entropy -= estimated_mutual_info
        
        return max(total_entropy, 0.0)
    
    @staticmethod
    def resistance_score(effectiveness_measures: Dict[str, float],
                        deployment_weights: Dict[str, float] = None) -> float:
        """
        Calculate resistance score using equation from paper:
        R(T) = sum(w_i * (1 - E_i)) / sum(w_i)
        """
        if not effectiveness_measures:
            return 0.0
        
        if deployment_weights is None:
            # Default equal weights
            deployment_weights = {tool: 1.0 for tool in effectiveness_measures.keys()}
        
        numerator = sum(deployment_weights.get(tool, 1.0) * (1 - effectiveness)
                       for tool, effectiveness in effectiveness_measures.items())
        denominator = sum(deployment_weights.get(tool, 1.0) 
                         for tool in effectiveness_measures.keys())
        
        return numerator / denominator if denominator > 0 else 0.0


def _are_related_features(feature1: str, feature2: str) -> bool:
    """Determine if two fingerprinting features are related"""
    related_groups = [
        {'canvas', 'webgl'},  # Both graphics-related
        {'accelerometer', 'gyroscope', 'magnetometer'},  # Motion sensors
        {'cookies', 'local_storage', 'indexed_db'}  # Storage mechanisms
    ]
    
    for group in related_groups:
        if any(f1 in feature1.lower() for f1 in group) and \
           any(f2 in feature2.lower() for f2 in group):
            return True
    
    return False


# network_analyzer.py
"""
Network traffic analysis for tracking detection
"""

import requests
import socket
import ssl
import json
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Tuple
import concurrent.futures
import time


class NetworkTrafficAnalyzer:
    """Analyze network traffic for tracking indicators"""
    
    def __init__(self):
        self.known_trackers = self._load_tracker_lists()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def _load_tracker_lists(self) -> Set[str]:
        """Load known tracker domains from various sources"""
        # In a real implementation, you'd load from:
        # - EasyList
        # - EasyPrivacy
        # - uBlock Origin filters
        # - Disconnect.me lists
        
        return {
            'google-analytics.com',
            'googletagmanager.com',
            'facebook.com',
            'doubleclick.net',
            'googlesyndication.com',
            'amazon-adsystem.com',
            'adsystem.amazon.com',
            'scorecardresearch.com',
            'quantserve.com',
            'outbrain.com',
            'taboola.com',
            'addthis.com',
            'sharethis.com'
        }
    
    def analyze_domain_requests(self, domain: str) -> Dict[str, any]:
        """Analyze network requests for a domain"""
        url = f"https://{domain}"
        
        try:
            # Get main page
            response = self.session.get(url, timeout=10)
            
            # Parse content for external requests
            external_requests = self._extract_external_requests(response.text, domain)
            
            # Classify requests
            classification = self._classify_requests(external_requests)
            
            # Check for tracking indicators
            tracking_indicators = self._detect_tracking_indicators(external_requests)
            
            return {
                'total_external_requests': len(external_requests),
                'tracker_requests': classification['trackers'],
                'cdn_requests': classification['cdn'],
                'analytics_requests': classification['analytics'],
                'advertising_requests': classification['advertising'],
                'tracking_indicators': tracking_indicators,
                'third_party_domains': list(set(urlparse(req).netloc for req in external_requests))
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'total_external_requests': 0,
                'tracker_requests': [],
                'tracking_indicators': {}
            }
    
    def _extract_external_requests(self, html_content: str, base_domain: str) -> List[str]:
        """Extract external requests from HTML content"""
        import re
        
        # Find script, img, link, iframe sources
        patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'<img[^>]+src=["\']([^"\']+)["\']',
            r'<link[^>]+href=["\']([^"\']+)["\']',
            r'<iframe[^>]+src=["\']([^"\']+)["\']'
        ]
        
        external_requests = []
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if self._is_external_request(match, base_domain):
                    external_requests.append(match)
        
        return external_requests
    
    def _is_external_request(self, url: str, base_domain: str) -> bool:
        """Check if URL is external to base domain"""
        if url.startswith('//'):
            url = 'https:' + url
        elif url.startswith('/'):
            return False
        elif not url.startswith('http'):
            return False
        
        try:
            parsed = urlparse(url)
            return parsed.netloc != base_domain and base_domain not in parsed.netloc
        except:
            return False
    
    def _classify_requests(self, requests: List[str]) -> Dict[str, List[str]]:
        """Classify requests by type"""
        classification = {
            'trackers': [],
            'cdn': [],
            'analytics': [],
            'advertising': []
        }
        
        cdn_indicators = ['cdn', 'static', 'assets', 'cloudflare', 'amazonaws']
        analytics_indicators = ['analytics', 'tracking', 'stats', 'metrics']
        ad_indicators = ['ads', 'doubleclick', 'adsystem', 'advertising']
        
        for request in requests:
            domain = urlparse(request).netloc
            
            if domain in self.known_trackers:
                classification['trackers'].append(request)
            elif any(indicator in domain for indicator in cdn_indicators):
                classification['cdn'].append(request)
            elif any(indicator in domain for indicator in analytics_indicators):
                classification['analytics'].append(request)
            elif any(indicator in domain for indicator in ad_indicators):
                classification['advertising'].append(request)
        
        return classification
    
    def _detect_tracking_indicators(self, requests: List[str]) -> Dict[str, bool]:
        """Detect specific tracking indicators"""
        indicators = {
            'google_analytics': False,
            'facebook_pixel': False,
            'adobe_analytics': False,
            'hotjar': False,
            'mixpanel': False,
            'segment': False
        }
        
        tracking_patterns = {
            'google_analytics': ['google-analytics.com', 'googletagmanager.com'],
            'facebook_pixel': ['facebook.com/tr', 'facebook.net'],
            'adobe_analytics': ['omtrdc.net', 'adobe.com'],
            'hotjar': ['hotjar.com'],
            'mixpanel': ['mixpanel.com'],
            'segment': ['segment.com', 'segment.io']
        }
        
        for request in requests:
            for tracker, patterns in tracking_patterns.items():
                if any(pattern in request for pattern in patterns):
                    indicators[tracker] = True
        
        return indicators


if __name__ == "__main__":
    # Run specific test modules
    import sys
    
    if len(sys.argv) > 1:
        test_module = sys.argv[1]
        
        if test_module == "entropy":
            # Test entropy calculations
            calc = EntropyCalculator()
            
            # Test canvas entropy
            canvas_data = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAADICAYAAABS39xVAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAN1wAADdcBQiibeAAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAANCSURBVHic7dYxAQAACAhEoEYDGAAAOwB//+5kAVNkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaBkWQGgZFkBoGRZAaC0AVJbgOPDcAAAAAElFTkSuQmCC"
            entropy = calc.canvas_entropy(canvas_data)
            print(f"Canvas entropy: {entropy:.2f} bits")
            
            # Test combined entropy
            individual = {
                'canvas': 13.1,
                'webgl': 9.2,
                'audio': 7.3,
                'cookies': 11.2
            }
            combined = calc.combined_entropy(individual)
            print(f"Combined entropy: {combined:.2f} bits")
            
        elif test_module == "network":
            # Test network analysis
            analyzer = NetworkTrafficAnalyzer()
            result = analyzer.analyze_domain_requests("example.com")
            print(json.dumps(result, indent=2))
            
        elif test_module == "validation":
            # Test validation functions
            import tempfile
            import os
            
            # Create sample data
            temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
            from web_tracking_analyzer import DatabaseManager, TrackingResult
            
            db = DatabaseManager(temp_db.name)
            
            # Insert sample data
            for i in range(100):
                result = TrackingResult(
                    domain=f"test{i}.com",
                    timestamp=datetime.now(),
                    protection_tool=["none", "ublock", "privacy_badger"][i % 3],
                    browser="chrome",
                    platform="desktop",
                    cookies_detected=np.random.randint(0, 20),
                    third_party_cookies=np.random.randint(0, 10),
                    canvas_fingerprinting=np.random.choice([True, False]),
                    webgl_fingerprinting=np.random.choice([True, False]),
                    audio_fingerprinting=np.random.choice([True, False]),
                    sensor_access=np.random.choice([True, False]),
                    local_storage_used=True,
                    indexed_db_used=False,
                    etag_tracking=False,
                    requests_blocked=np.random.randint(0, 50),
                    total_requests=np.random.randint(50, 200),
                    load_time=np.random.uniform(1.0, 5.0),
                    entropy_bits=np.random.uniform(10, 30),
                    protection_score=np.random.uniform(30, 95)
                )
                db.insert_result(result)
            
            # Run validation
            df = db.get_results()
            report = validate_experimental_design(df)
            print(json.dumps(report, indent=2, default=str))
            
            # Cleanup
            os.unlink(temp_db.name)
    
    else:
        print("Available test modules:")
        print("  entropy - Test entropy calculations")
        print("  network - Test network analysis")
        print("  validation - Test experimental validation")
        print("\nUsage: python testing_utils.py [module_name]") calculation for two-sample t-test
        delta = cohens_d * np.sqrt(n_harmonic / 2)
        alpha = 0.05
        t_critical = stats.t.ppf(1 - alpha/2, n1 + n2 - 2)
        
        power = 1 - stats.t.cdf(t_critical - delta, n1 + n2 - 2) + \
                stats.t.cdf(-t_critical - delta, n1 + n2 - 2)
        
        return {
            'effect_size': cohens_d,
            'achieved_power': power,
            'sample_size_adequate': power >= 0.8
        }


class ReproducibilityChecker:
    """Checks reproducibility of results"""
    
    @staticmethod
    def cross_validation_stability(df: pd.DataFrame, n_folds: int = 5, 
                                  n_repeats: int = 10) -> Dict[str, List[float]]:
        """Check stability across cross-validation folds"""
        
        from sklearn.model_selection import StratifiedKFold
        
        results = {
            'fold_means': [],
            'fold_stds': [],
            'cv_coefficient_variation': []
        }
        
        y = df['protection_tool']
        
        for repeat in range(n_repeats):
            skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=repeat)
            fold_scores = []
            
            for train_idx, test_idx in skf.split(df, y):
                test_fold = df.iloc[test_idx]
                fold_mean = test_fold['protection_score'].mean()
                fold_scores.append(fold_mean)
            
            results['fold_means'].extend(fold_scores)
            results['fold_stds'].append(np.std(fold_scores))
            results['cv_coefficient_variation'].append(np.std(fold_scores) / np.mean(fold_scores))
        
        return results
    
    @staticmethod
    def bootstrap_confidence_intervals(data: pd.Series, n_bootstrap: int = 1000, 
                                     confidence: float = 0.95) -> Dict[str, float]:
        """Calculate bootstrap confidence intervals"""
        
        bootstrap_means = []
        
        for _ in range(n_bootstrap):
            bootstrap_sample = np.random.choice(data, size=len(data), replace=True)
            bootstrap_means.append(np.mean(bootstrap_sample))
        
        alpha = 1 - confidence
        lower_percentile = (alpha/2) * 100
        upper_percentile = (1 - alpha/2) * 100
        
        ci_lower = np.percentile(bootstrap_means, lower_percentile)
        ci_upper = np.percentile(bootstrap_means, upper_percentile)
        
        return {
            'mean': np.mean(data),
            'ci_lower': ci_lower,
            'ci_upper': ci_upper,
            'ci_width': ci_upper - ci_lower,
            'bootstrap_std': np.std(bootstrap_means)
        }


def validate_experimental_design(df: pd.DataFrame) -> Dict[str, Any]:
    """Comprehensive validation of experimental design"""
    
    validator = ExperimentValidator()
    repro_checker = ReproducibilityChecker()
    
    validation_report = {
        'sample_sizes': {},
        'normality_tests': {},
        'randomization_checks': {},
        'power_analysis': {},
        'reproducibility': {}
    }
    
    # Check sample sizes by group
    for tool in df['protection_tool'].unique():
        tool_data = df[df['protection_tool'] == tool]['protection_score']
        validation_report['sample_sizes'][tool] = len(tool_data)
        
        # Normality tests
        validation_report['normality_tests'][tool] = validator.check_normality(tool_data)
    
    # Randomization checks
    validation_report['randomization_checks'] = validator.validate_randomization(df)
    
    # Power