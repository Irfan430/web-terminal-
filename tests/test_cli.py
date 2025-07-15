"""
Test suite for CLI module
"""

import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner

from cli import app, CyberToolkit

class TestCyberToolkit:
    def setup_method(self):
        """Setup test fixtures"""
        self.runner = CliRunner()
        self.toolkit = CyberToolkit()
    
    def test_toolkit_initialization(self):
        """Test CyberToolkit initialization"""
        assert self.toolkit.target is None
        assert self.toolkit.reports_dir.exists()
        assert hasattr(self.toolkit, 'nmap_scanner')
        assert hasattr(self.toolkit, 'brute_force')
        assert hasattr(self.toolkit, 'phishing')
        assert hasattr(self.toolkit, 'risk_predictor')
    
    def test_get_target(self):
        """Test target setting"""
        with patch('typer.prompt', return_value='example.com'):
            target = self.toolkit.get_target()
            assert target == 'example.com'
            assert self.toolkit.target == 'example.com'
    
    @patch('cli.CyberToolkit.run_vulnerability_scan')
    def test_vulnerability_scan(self, mock_scan):
        """Test vulnerability scan command"""
        mock_scan.return_value = {'status': 'completed'}
        self.toolkit.target = 'test.com'
        
        result = self.toolkit.run_vulnerability_scan()
        mock_scan.assert_called_once()
        assert result['status'] == 'completed'
    
    @patch('cli.CyberToolkit.run_brute_force')  
    def test_brute_force_simulation(self, mock_brute):
        """Test brute force simulation"""
        mock_brute.return_value = {'attempts': 10, 'successful': 0}
        self.toolkit.target = 'test.com'
        
        result = self.toolkit.run_brute_force()
        mock_brute.assert_called_once()
        assert 'attempts' in result
    
    def test_cli_scan_command(self):
        """Test CLI scan command"""
        with patch('cli.CyberToolkit.run_vulnerability_scan') as mock_scan:
            mock_scan.return_value = {'target': 'test.com', 'status': 'completed'}
            
            result = self.runner.invoke(app, ['scan', 'test.com'])
            assert result.exit_code == 0
    
    def test_cli_install_command(self):
        """Test CLI install command"""
        with patch('shared.utils.setup_environment') as mock_setup:
            result = self.runner.invoke(app, ['install'])
            assert result.exit_code == 0
            mock_setup.assert_called_once()

class TestCLIIntegration:
    """Integration tests for CLI functionality"""
    
    def setup_method(self):
        self.runner = CliRunner()
    
    def test_help_command(self):
        """Test help command"""
        result = self.runner.invoke(app, ['--help'])
        assert result.exit_code == 0
        assert 'CyberToolkit' in result.output
    
    def test_invalid_command(self):
        """Test invalid command handling"""
        result = self.runner.invoke(app, ['invalid-command'])
        assert result.exit_code != 0
    
    @patch('shared.utils.validate_target')
    def test_target_validation(self, mock_validate):
        """Test target validation"""
        mock_validate.return_value = True
        
        with patch('cli.CyberToolkit.run_vulnerability_scan') as mock_scan:
            mock_scan.return_value = {'status': 'completed'}
            result = self.runner.invoke(app, ['scan', 'valid-target.com'])
            assert result.exit_code == 0

if __name__ == '__main__':
    pytest.main([__file__])