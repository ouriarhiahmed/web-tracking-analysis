#!/bin/bash
# setup.sh - Setup script for the web tracking analysis framework

set -e

echo "Web Tracking Protection Analysis Framework Setup"
echo "================================================"

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)" 2>/dev/null; then
    echo "Error: Python 3.8 or higher is required"
    echo "Current version: $(python3 --version)"
    exit 1
fi

echo "✓ Python version check passed"

# Create project directory structure
echo "Creating directory structure..."
mkdir -p {results,plots,logs,extensions,data,config}

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install additional system dependencies based on OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Detected Linux system..."
    
    # Check if running as root or with sudo access
    if command -v apt-get &> /dev/null; then
        echo "Installing system dependencies with apt..."
        sudo apt-get update
        sudo apt-get install -y wget curl unzip gnupg
        
        # Install Chrome
        if ! command -v google-chrome &> /dev/null; then
            echo "Installing Google Chrome..."
            wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
            echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google.list
            sudo apt-get update
            sudo apt-get install -y google-chrome-stable
        fi
        
        # Install Firefox
        if ! command -v firefox &> /dev/null; then
            echo "Installing Firefox..."
            sudo apt-get install -y firefox
        fi
        
    elif command -v yum &> /dev/null; then
        echo "Installing system dependencies with yum..."
        sudo yum install -y wget curl unzip
        # Add Chrome and Firefox installation for CentOS/RHEL
    fi
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Detected macOS system..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install browsers if not present
    if ! command -v /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome &> /dev/null; then
        echo "Installing Google Chrome..."
        brew install --cask google-chrome
    fi
    
    if ! command -v firefox &> /dev/null; then
        echo "Installing Firefox..."
        brew install --cask firefox
    fi
fi

# Download ChromeDriver
echo "Setting up ChromeDriver..."
CHROMEDRIVER_VERSION=$(curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE)
wget -O chromedriver.zip "https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip"
unzip chromedriver.zip
chmod +x chromedriver
sudo mv chromedriver /usr/local/bin/
rm chromedriver.zip

# Download GeckoDriver for Firefox
echo "Setting up GeckoDriver..."
GECKODRIVER_VERSION=$(curl -s "https://api.github.com/repos/mozilla/geckodriver/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
wget -O geckodriver.tar.gz "https://github.com/mozilla/geckodriver/releases/download/${GECKODRIVER_VERSION}/geckodriver-${GECKODRIVER_VERSION}-linux64.tar.gz"
tar -xzf geckodriver.tar.gz
chmod +x geckodriver
sudo mv geckodriver /usr/local/bin/
rm geckodriver.tar.gz

# Create configuration files
echo "Creating configuration files..."

# Create sample experiment config
cat > config/experiment_config.json << EOF
{
    "experiment_name": "Web Tracking Protection Analysis",
    "domains_file": "data/domains.json",
    "output_dir": "results",
    "browsers": ["chrome", "firefox"],
    "protection_tools": ["none", "ublock_origin", "privacy_badger", "firefox_etp"],
    "repetitions": 3,
    "timeout": 30,
    "headless": true,
    "geographic_proxies": false,
    "parallel_workers": 2,
    "delay_between_requests": 2,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    ]
}
EOF

# Create logging configuration
cat > config/logging_config.json << EOF
{
    "version": 1,
    "disable_existing_loggers": false,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s"
        }
    },
    "handlers": {
        "default": {
            "level": "INFO",
            "formatter": "standard",
            "class": "logging.StreamHandler"
        },
        "file": {
            "level": "DEBUG",
            "formatter": "detailed",
            "class": "logging.FileHandler",
            "filename": "logs/tracking_analysis.log",
            "mode": "a"
        }
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": "DEBUG",
            "propagate": false
        }
    }
}
EOF

# Create environment file
cat > .env << EOF
# Web Tracking Analysis Environment Configuration
PYTHONPATH=.
DATABASE_URL=sqlite:///tracking_results.db
LOG_LEVEL=INFO
HEADLESS_MODE=true
TIMEOUT=30
MAX_WORKERS=2
EOF

# Set up pre-commit hooks
echo "Setting up pre-commit hooks..."
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.8
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=88, --extend-ignore=E203]
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args: ["--profile", "black"]
EOF

# Install pre-commit
pip install pre-commit
pre-commit install

# Create data validation script
cat > scripts/validate_setup.py << 'EOF'
#!/usr/bin/env python3
"""
Validation script to test the setup
"""

import sys
import subprocess
import importlib
import os
from pathlib import Path

def check_python_packages():
    """Check if all required packages are installed"""
    required_packages = [
        'selenium', 'pandas', 'numpy', 'scipy', 'matplotlib', 
        'seaborn', 'sklearn', 'requests', 'dns'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package.replace('-', '_'))
            print(f"✓ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package}")
    
    return len(missing_packages) == 0

def check_browser_drivers():
    """Check if browser drivers are available"""
    drivers = {
        'chromedriver': 'ChromeDriver',
        'geckodriver': 'GeckoDriver (Firefox)'
    }
    
    all_present = True
    for driver, name in drivers.items():
        try:
            subprocess.run([driver, '--version'], 
                         capture_output=True, check=True)
            print(f"✓ {name}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"✗ {name}")
            all_present = False
    
    return all_present

def check_directory_structure():
    """Check if required directories exist"""
    required_dirs = ['results', 'plots', 'logs', 'extensions', 'data', 'config']
    
    all_present = True
    for directory in required_dirs:
def check_directory_structure():
    """Check if required directories exist"""
    required_dirs = ['results', 'plots', 'logs', 'extensions', 'data', 'config']
    
    all_present = True
    for directory in required_dirs:
        if Path(directory).exists():
            print(f"✓ {directory}/")
        else:
            print(f"✗ {directory}/")
            all_present = False
    
    return all_present

def check_config_files():
    """Check if configuration files exist"""
    config_files = [
        'config/experiment_config.json',
        'config/logging_config.json',
        'data/domains.json'
    ]
    
    all_present = True
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"✓ {config_file}")
        else:
            print(f"✗ {config_file}")
            all_present = False
    
    return all_present

def main():
    """Run all validation checks"""
    print("Web Tracking Analysis Framework - Setup Validation")
    print("=" * 60)
    
    checks = [
        ("Python Packages", check_python_packages),
        ("Browser Drivers", check_browser_drivers),
        ("Directory Structure", check_directory_structure),
        ("Configuration Files", check_config_files)
    ]
    
    all_passed = True
    
    for check_name, check_func in checks:
        print(f"\n{check_name}:")
        print("-" * len(check_name))
        if not check_func():
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All validation checks passed! Framework is ready to use.")
        return 0
    else:
        print("✗ Some validation checks failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

# Make the validation script executable
chmod +x scripts/validate_setup.py

# Create run script
cat > scripts/run_experiment.sh << 'EOF'
#!/bin/bash
# run_experiment.sh - Script to run the web tracking experiment

set -e

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export PYTHONPATH=.
export DISPLAY=:99

# Check if running in headless environment
if [ "$HEADLESS" = "true" ] || [ "$CI" = "true" ]; then
    # Start virtual display for headless environments
    if command -v Xvfb &> /dev/null; then
        echo "Starting virtual display..."
        Xvfb :99 -screen 0 1920x1080x24 &
        XVFB_PID=$!
        sleep 2
    fi
fi

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$XVFB_PID" ]; then
        kill $XVFB_PID 2>/dev/null || true
    fi
    
    # Kill any remaining browser processes
    pkill -f chrome 2>/dev/null || true
    pkill -f firefox 2>/dev/null || true
    pkill -f geckodriver 2>/dev/null || true
    pkill -f chromedriver 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Parse command line arguments
EXPERIMENT_TYPE="full"
DOMAINS_FILE="data/domains.json"
OUTPUT_DIR="results"

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            EXPERIMENT_TYPE="$2"
            shift 2
            ;;
        --domains)
            DOMAINS_FILE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --type TYPE       Experiment type: full, quick, test (default: full)"
            echo "  --domains FILE    Path to domains file (default: data/domains.json)"
            echo "  --output DIR      Output directory (default: results)"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run experiment based on type
case $EXPERIMENT_TYPE in
    "test")
        echo "Running test experiment (single domain, minimal tools)..."
        python3 web_tracking_analyzer.py --test-mode
        ;;
    "quick")
        echo "Running quick experiment (reduced repetitions)..."
        python3 web_tracking_analyzer.py --repetitions 1 --domains "$DOMAINS_FILE" --output "$OUTPUT_DIR"
        ;;
    "full")
        echo "Running full experiment..."
        python3 web_tracking_analyzer.py --domains "$DOMAINS_FILE" --output "$OUTPUT_DIR"
        ;;
    *)
        echo "Unknown experiment type: $EXPERIMENT_TYPE"
        exit 1
        ;;
esac

echo "Experiment completed successfully!"
echo "Results saved in: $OUTPUT_DIR"
EOF

# Make run script executable
chmod +x scripts/run_experiment.sh

# Create analysis script
cat > scripts/analyze_results.py << 'EOF'
#!/usr/bin/env python3
"""
Script to analyze experimental results and generate reports
"""

import argparse
import sys
from pathlib import Path
import json
from datetime import datetime

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from web_tracking_analyzer import DatabaseManager, StatisticalAnalyzer, Visualizer

def main():
    parser = argparse.ArgumentParser(description='Analyze web tracking experiment results')
    parser.add_argument('--database', default='tracking_results.db',
                       help='Path to results database')
    parser.add_argument('--output-dir', default='analysis_output',
                       help='Output directory for analysis results')
    parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='json',
                       help='Output format for reports')
    parser.add_argument('--plots', action='store_true',
                       help='Generate visualization plots')
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Initialize analyzer
    db = DatabaseManager(args.database)
    analyzer = StatisticalAnalyzer(db)
    
    # Load results
    df = analyzer.load_results()
    
    if df.empty:
        print("No results found in database.")
        return 1
    
    print(f"Analyzing {len(df)} experimental results...")
    
    # Generate comprehensive report
    report = analyzer.generate_report(str(output_dir / "analysis_report.json"))
    
    print(f"Analysis completed. Results saved in {output_dir}")
    
    # Generate plots if requested
    if args.plots:
        print("Generating visualizations...")
        plots_dir = output_dir / "plots"
        plots_dir.mkdir(exist_ok=True)
        Visualizer.plot_protection_effectiveness(df, str(plots_dir))
        print(f"Plots saved in {plots_dir}")
    
    # Print summary
    print("\nExperiment Summary:")
    print("-" * 40)
    print(f"Total samples: {len(df)}")
    print(f"Unique domains: {df['domain'].nunique()}")
    print(f"Protection tools tested: {', '.join(df['protection_tool'].unique())}")
    print(f"Mean protection score: {df['protection_score'].mean():.1f}%")
    print(f"Standard deviation: {df['protection_score'].std():.1f}%")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

# Make analysis script executable
chmod +x scripts/analyze_results.py

# Create Docker setup script
cat > scripts/setup_docker.sh << 'EOF'
#!/bin/bash
# setup_docker.sh - Setup Docker environment for the framework

set -e

echo "Setting up Docker environment..."

# Build Docker image
docker-compose build

# Create necessary directories in container
docker-compose run --rm tracking-analyzer mkdir -p /app/{results,plots,logs,extensions}

# Download browser extensions (this needs to be done manually)
echo ""
echo "Manual step required:"
echo "Please download the following browser extensions and place them in the extensions/ directory:"
echo ""
echo "1. uBlock Origin:"
echo "   - Visit: https://github.com/gorhill/uBlock/releases"
echo "   - Download the .crx file for Chrome"
echo ""
echo "2. Privacy Badger:"
echo "   - Visit: https://github.com/EFForg/privacybadger/releases"
echo "   - Download the .crx file for Chrome"
echo ""
echo "Once extensions are downloaded, you can run the experiment with:"
echo "  docker-compose up"
echo ""
EOF

chmod +x scripts/setup_docker.sh

# Create maintenance script
cat > scripts/maintenance.sh << 'EOF'
#!/bin/bash
# maintenance.sh - Maintenance and cleanup script

set -e

function show_help() {
    echo "Web Tracking Analysis Framework - Maintenance Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  clean-results    Remove all result files and databases"
    echo "  clean-logs       Remove all log files"
    echo "  clean-cache      Remove Python cache files"
    echo "  clean-all        Remove all generated files"
    echo "  update-deps      Update Python dependencies"
    echo "  backup           Create backup of results and configuration"
    echo "  restore BACKUP   Restore from backup file"
    echo "  help             Show this help message"
}

function clean_results() {
    echo "Cleaning results..."
    rm -rf results/*
    rm -f *.db
    rm -f analysis_report.json
    echo "Results cleaned."
}

function clean_logs() {
    echo "Cleaning logs..."
    rm -rf logs/*
    echo "Logs cleaned."
}

function clean_cache() {
    echo "Cleaning Python cache..."
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -name "*.pyc" -delete 2>/dev/null || true
    echo "Cache cleaned."
}

function clean_all() {
    clean_results
    clean_logs
    clean_cache
    rm -rf plots/*
    echo "All generated files cleaned."
}

function update_deps() {
    echo "Updating dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install --upgrade -r requirements.txt
    echo "Dependencies updated."
}

function backup_data() {
    backup_name="backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    echo "Creating backup: $backup_name"
    
    tar -czf "$backup_name" \
        --exclude='venv' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        results/ config/ data/ *.db 2>/dev/null || true
    
    echo "Backup created: $backup_name"
}

function restore_data() {
    backup_file="$1"
    if [ ! -f "$backup_file" ]; then
        echo "Backup file not found: $backup_file"
        exit 1
    fi
    
    echo "Restoring from backup: $backup_file"
    tar -xzf "$backup_file"
    echo "Restore completed."
}

# Main script logic
case "${1:-help}" in
    clean-results)
        clean_results
        ;;
    clean-logs)
        clean_logs
        ;;
    clean-cache)
        clean_cache
        ;;
    clean-all)
        clean_all
        ;;
    update-deps)
        update_deps
        ;;
    backup)
        backup_data
        ;;
    restore)
        if [ -z "$2" ]; then
            echo "Error: Please specify backup file"
            echo "Usage: $0 restore BACKUP_FILE"
            exit 1
        fi
        restore_data "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
EOF

chmod +x scripts/maintenance.sh

# Run validation
echo "Running setup validation..."
python3 scripts/validate_setup.py

# Final setup completion message
echo ""
echo "Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Review and customize the configuration in config/experiment_config.json"
echo "2. Add your target domains to data/domains.json"
echo "3. Download browser extensions to extensions/ directory (see README)"
echo "4. Run a test experiment: ./scripts/run_experiment.sh --type test"
echo "5. Run the full experiment: ./scripts/run_experiment.sh --type full"
echo ""
echo "For help and documentation, see:"
echo "- README.md for usage instructions"
echo "- config/ directory for configuration options"
echo "- scripts/ directory for utility scripts"
echo ""

# Create a comprehensive README
cat > README.md << 'EOF'
# Web Tracking Protection Methods: Experimental Framework

A comprehensive framework for analyzing web tracking technologies and protection methods, implementing the methodology described in the research paper "Web Tracking Protection Methods: A Comprehensive Review and Comparative Analysis of Modern Detection and Mitigation Strategies".

## Overview

This framework provides tools for:
- Automated web crawling and tracking detection
- Browser fingerprinting analysis
- Protection tool effectiveness measurement  
- Statistical analysis and visualization
- Reproducible experimental methodology

## Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd web-tracking-analysis
chmod +x setup.sh
./setup.sh

# Run a test experiment
./scripts/run_experiment.sh --type test

# Analyze results
./scripts/analyze_results.py --plots
```

## Installation

### Prerequisites
- Python 3.8+
- Chrome and/or Firefox browsers
- Git

### Setup
```bash
./setup.sh
```

This will:
- Create virtual environment
- Install dependencies
- Download browser drivers
- Create directory structure
- Run validation tests

## Configuration

### Experiment Configuration
Edit `config/experiment_config.json` to customize:
- Target domains and categories
- Protection tools to test
- Number of repetitions
- Browser settings

### Domain Lists
Add domains to `data/domains.json`:
```json
{
  "e-commerce": [
    {"domain": "example.com", "region": "US", "alexa_rank": 100}
  ]
}
```

### Browser Extensions
Download browser extensions to `extensions/`:
- uBlock Origin: Place `ublock_origin.crx` in extensions/
- Privacy Badger: Place `privacy_badger.crx` in extensions/

## Usage

### Running Experiments

```bash
# Full experiment (all domains, all tools, full repetitions)
./scripts/run_experiment.sh --type full

# Quick experiment (reduced repetitions)  
./scripts/run_experiment.sh --type quick

# Test experiment (single domain)
./scripts/run_experiment.sh --type test
```

### Analysis

```bash
# Generate analysis report
./scripts/analyze_results.py

# Generate with plots
./scripts/analyze_results.py --plots

# Custom output directory
./scripts/analyze_results.py --output-dir custom_analysis --plots
```

### Docker Deployment

```bash
# Setup Docker environment
./scripts/setup_docker.sh

# Run with Docker
docker-compose up
```

## Framework Components

### Core Modules

- `web_tracking_analyzer.py` - Main framework implementation
- `test_framework.py` - Unit tests and validation
- `entropy_calculator.py` - Information theory calculations
- `network_analyzer.py` - Network traffic analysis

### Key Classes

- `WebCrawler` - Automated domain analysis
- `FingerprintingDetector` - Tracking technology detection
- `ProtectionToolManager` - Browser/extension management
- `StatisticalAnalyzer` - Results analysis
- `DatabaseManager` - Data persistence

### Data Collection

The framework collects:
- Cookie usage (first-party, third-party)
- Fingerprinting techniques (canvas, WebGL, audio, sensors)
- Storage mechanisms (localStorage, IndexedDB)
- Network requests and blocking effectiveness
- Load times and performance metrics

### Statistical Analysis

Implements methodology from the paper:
- Cohen's d effect size calculations
- Cross-validation with multiple random seeds
- Bootstrap confidence intervals
- ANOVA with post-hoc testing
- False discovery rate control

## Methodology

Based on the systematic review methodology:

1. **Controlled Environment**: Fixed browser versions, containerized execution
2. **Bias Mitigation**: Geographic diversity, multiple repetitions, randomization
3. **Statistical Rigor**: Power analysis, effect sizes, confidence intervals
4. **Reproducibility**: Version control, open source, persistent identifiers

## Results

Results are stored in:
- `tracking_results.db` - SQLite database with all measurements
- `results/` - Analysis reports and summaries
- `plots/` - Visualization outputs

### Key Metrics

- Protection effectiveness scores
- Entropy measurements (bits)
- Blocking accuracy (precision/recall)
- Cross-platform comparisons

## Maintenance

```bash
# Clean results
./scripts/maintenance.sh clean-results

# Update dependencies
./scripts/maintenance.sh update-deps

# Backup data
./scripts/maintenance.sh backup

# Full cleanup
./scripts/maintenance.sh clean-all
```

## Testing

```bash
# Run unit tests
python -m pytest test_framework.py -v

# Run validation tests
python scripts/validate_setup.py

# Test specific components
python testing_utils.py entropy
python testing_utils.py network
python testing_utils.py validation
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Run validation suite
5. Submit pull request

## Citation

If you use this framework in your research, please cite:

```
@article{ouriarhi2024tracking,
  title={Web Tracking Protection Methods: A Comprehensive Review and Comparative Analysis of Modern Detection and Mitigation Strategies},
  author={Ouriarhi, Ahmed and Ikkou, Youness},
  journal={Under Review},
  year={2024},
  institution={LABO MATSI, École Supérieure de Technologie, Université Mohammed Premier}
}
```

## License

This project is licensed under the Creative Commons Attribution 4.0 International License (CC-BY 4.0).

## Support

For issues and questions:
- Create GitHub issue
- Email: ahmed.ouriarhi@ump.ac.ma
- Documentation: See `docs/` directory

## Acknowledgments

- LABO MATSI research team
- Open source browser extension developers
- Privacy research community
EOF

echo "README.md created successfully!"
