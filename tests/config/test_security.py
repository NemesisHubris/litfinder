"""
Tests for security configuration and migration.

Tests the security settings registration, migration from old settings,
and proxy authentication configuration.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def temp_config_dir():
    """Create a temporary config directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir)
        security_dir = config_dir / "security"
        security_dir.mkdir(parents=True, exist_ok=True)
        yield security_dir


@pytest.fixture
def mock_logger():
    """Mock logger to capture log messages."""
    return MagicMock()


class TestSecurityMigration:
    """Tests for migrating legacy security settings."""

    def test_migrate_use_cwa_auth_true(self, temp_config_dir, mock_logger):
        """Test migrating USE_CWA_AUTH=True to AUTH_METHOD='cwa'."""
        # Create legacy config
        config_file = temp_config_dir / "config.json"
        legacy_config = {
            "USE_CWA_AUTH": True,
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD_HASH": "hashed_password"
        }
        config_file.write_text(json.dumps(legacy_config, indent=2))

        # Mock load_config_file to return our test config, and the paths
        with patch('shelfmark.config.security.load_config_file', return_value=legacy_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        # Verify migration - read the actual file
        migrated_config = json.loads(config_file.read_text())
        assert migrated_config["AUTH_METHOD"] == "cwa"
        assert "USE_CWA_AUTH" not in migrated_config

    def test_migrate_use_cwa_auth_false_with_credentials(self, temp_config_dir, mock_logger):
        """Test migrating USE_CWA_AUTH=False with credentials to AUTH_METHOD='builtin'."""
        config_file = temp_config_dir / "config.json"
        legacy_config = {
            "USE_CWA_AUTH": False,
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD_HASH": "hashed_password"
        }
        config_file.write_text(json.dumps(legacy_config, indent=2))

        with patch('shelfmark.config.security.load_config_file', return_value=legacy_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        migrated_config = json.loads(config_file.read_text())
        assert migrated_config["AUTH_METHOD"] == "builtin"
        assert "USE_CWA_AUTH" not in migrated_config

    def test_migrate_use_cwa_auth_false_without_credentials(self, temp_config_dir, mock_logger):
        """Test migrating USE_CWA_AUTH=False without credentials to AUTH_METHOD='none'."""
        config_file = temp_config_dir / "config.json"
        legacy_config = {
            "USE_CWA_AUTH": False
        }
        config_file.write_text(json.dumps(legacy_config, indent=2))

        with patch('shelfmark.config.security.load_config_file', return_value=legacy_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        migrated_config = json.loads(config_file.read_text())
        assert migrated_config["AUTH_METHOD"] == "none"
        assert "USE_CWA_AUTH" not in migrated_config

    def test_migrate_restrict_settings_to_admin(self, temp_config_dir, mock_logger):
        """Test migrating RESTRICT_SETTINGS_TO_ADMIN to CWA_RESTRICT_SETTINGS_TO_ADMIN."""
        config_file = temp_config_dir / "config.json"
        legacy_config = {
            "AUTH_METHOD": "cwa",
            "RESTRICT_SETTINGS_TO_ADMIN": True
        }
        config_file.write_text(json.dumps(legacy_config, indent=2))

        with patch('shelfmark.config.security.load_config_file', return_value=legacy_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        migrated_config = json.loads(config_file.read_text())
        assert migrated_config["CWA_RESTRICT_SETTINGS_TO_ADMIN"] is True
        assert "RESTRICT_SETTINGS_TO_ADMIN" not in migrated_config

    def test_migrate_preserves_existing_auth_method(self, temp_config_dir, mock_logger):
        """Test that existing AUTH_METHOD is not overwritten during migration."""
        config_file = temp_config_dir / "config.json"
        legacy_config = {
            "USE_CWA_AUTH": True,
            "AUTH_METHOD": "proxy"  # Already has new format
        }
        config_file.write_text(json.dumps(legacy_config, indent=2))

        with patch('shelfmark.config.security.load_config_file', return_value=legacy_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        migrated_config = json.loads(config_file.read_text())
        assert migrated_config["AUTH_METHOD"] == "proxy"  # Should not change
        assert "USE_CWA_AUTH" not in migrated_config

    def test_migrate_handles_missing_config_file(self, temp_config_dir, mock_logger):
        """Test that migration handles missing config file gracefully."""
        with patch('shelfmark.config.security.load_config_file', side_effect=FileNotFoundError()):
            with patch('shelfmark.config.security.logger', mock_logger):
                from shelfmark.config.security import _migrate_security_settings
                _migrate_security_settings()

        mock_logger.debug.assert_any_call("No existing security config file found - nothing to migrate")

    def test_migrate_no_changes_needed(self, temp_config_dir, mock_logger):
        """Test migration when no changes are needed."""
        config_file = temp_config_dir / "config.json"
        modern_config = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD_HASH": "hashed_password"
        }
        config_file.write_text(json.dumps(modern_config, indent=2))

        with patch('shelfmark.config.security.load_config_file', return_value=modern_config.copy()):
            with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
                with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                    with patch('shelfmark.config.security.logger', mock_logger):
                        from shelfmark.config.security import _migrate_security_settings
                        _migrate_security_settings()

        # Config should remain unchanged
        final_config = json.loads(config_file.read_text())
        # File won't have been rewritten, so it should be the original
        assert final_config == modern_config
        mock_logger.debug.assert_any_call("No security settings migration needed")


class TestSecuritySettings:
    """Tests for security settings registration."""

    def test_security_settings_without_cwa(self):
        """Test that CWA option is not available when DB is not mounted."""
        # Patch CWA_DB_PATH where it's imported in the function
        with patch('shelfmark.config.env.CWA_DB_PATH', None):
            # Need to reload the module to pick up the patch
            import importlib
            import shelfmark.config.security
            importlib.reload(shelfmark.config.security)
            from shelfmark.config.security import security_settings

            fields = security_settings()
            
            # Find the AUTH_METHOD field
            auth_method_field = next((f for f in fields if f.key == "AUTH_METHOD"), None)
            assert auth_method_field is not None
            
            # CWA should not be in options
            option_values = [opt["value"] for opt in auth_method_field.options]
            assert "none" in option_values
            assert "builtin" in option_values
            assert "proxy" in option_values
            assert "cwa" not in option_values

    def test_security_settings_with_cwa(self):
        """Test that CWA option is available when DB is mounted."""
        # Create a mock path that exists
        mock_path = MagicMock()
        mock_path.exists.return_value = True
        
        with patch('shelfmark.config.env.CWA_DB_PATH', mock_path):
            import importlib
            import shelfmark.config.security
            importlib.reload(shelfmark.config.security)
            from shelfmark.config.security import security_settings

            fields = security_settings()
            
            # Find the AUTH_METHOD field
            auth_method_field = next((f for f in fields if f.key == "AUTH_METHOD"), None)
            assert auth_method_field is not None
            
            # CWA should be in options
            option_values = [opt["value"] for opt in auth_method_field.options]
            assert "cwa" in option_values

    def test_proxy_auth_fields_present(self):
        """Test that proxy auth configuration fields are present."""
        from shelfmark.config.security import security_settings

        fields = security_settings()
        field_keys = [f.key for f in fields]
        
        # Verify proxy auth fields exist
        assert "PROXY_AUTH_USER_HEADER" in field_keys
        assert "PROXY_AUTH_LOGOUT_URL" in field_keys
        assert "PROXY_AUTH_RESTRICT_SETTINGS_TO_ADMIN" in field_keys
        assert "PROXY_AUTH_ADMIN_GROUP_HEADER" in field_keys
        assert "PROXY_AUTH_ADMIN_GROUP_NAME" in field_keys

    def test_cwa_restrict_settings_field_present(self):
        """Test that CWA restrict settings field is present."""
        from shelfmark.config.security import security_settings

        fields = security_settings()
        field_keys = [f.key for f in fields]
        
        assert "CWA_RESTRICT_SETTINGS_TO_ADMIN" in field_keys


class TestPasswordValidation:
    """Tests for password validation in the on_save handler."""

    def test_on_save_validates_password_match(self):
        """Test that passwords must match."""
        from shelfmark.config.security import _on_save_security

        values = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD": "password123",
            "BUILTIN_PASSWORD_CONFIRM": "different_password"
        }

        result = _on_save_security(values)
        
        assert result["error"] is True
        assert "do not match" in result["message"]

    def test_on_save_validates_password_length(self):
        """Test that password must be at least 4 characters."""
        from shelfmark.config.security import _on_save_security

        values = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD": "abc",
            "BUILTIN_PASSWORD_CONFIRM": "abc"
        }

        result = _on_save_security(values)
        
        assert result["error"] is True
        assert "at least 4 characters" in result["message"]

    def test_on_save_requires_username_with_password(self):
        """Test that username is required when password is set."""
        from shelfmark.config.security import _on_save_security

        values = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_PASSWORD": "password123",
            "BUILTIN_PASSWORD_CONFIRM": "password123"
        }

        result = _on_save_security(values)
        
        assert result["error"] is True
        assert "Username cannot be empty" in result["message"]

    def test_on_save_hashes_password(self):
        """Test that password is properly hashed."""
        from shelfmark.config.security import _on_save_security

        values = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD": "password123",
            "BUILTIN_PASSWORD_CONFIRM": "password123"
        }

        result = _on_save_security(values)
        
        assert result["error"] is False
        assert "BUILTIN_PASSWORD_HASH" in result["values"]
        assert "BUILTIN_PASSWORD" not in result["values"]
        assert "BUILTIN_PASSWORD_CONFIRM" not in result["values"]
        # Hash should be different from raw password
        assert result["values"]["BUILTIN_PASSWORD_HASH"] != "password123"

    def test_on_save_preserves_existing_hash_when_no_password(self):
        """Test that existing password hash is preserved when password fields are empty."""
        from shelfmark.config.security import _on_save_security

        with patch('shelfmark.config.security.load_config_file') as mock_load:
            mock_load.return_value = {
                "BUILTIN_PASSWORD_HASH": "existing_hash"
            }

            values = {
                "AUTH_METHOD": "builtin",
                "BUILTIN_USERNAME": "admin"
            }

            result = _on_save_security(values)
            
            assert result["error"] is False
            assert result["values"]["BUILTIN_PASSWORD_HASH"] == "existing_hash"


class TestClearCredentials:
    """Tests for clearing built-in credentials."""

    def test_clear_credentials_removes_username_and_hash(self, temp_config_dir):
        """Test that clearing credentials removes username and password hash."""
        config_file = temp_config_dir / "config.json"
        config = {
            "AUTH_METHOD": "builtin",
            "BUILTIN_USERNAME": "admin",
            "BUILTIN_PASSWORD_HASH": "hashed_password"
        }
        config_file.write_text(json.dumps(config, indent=2))

        with patch('shelfmark.core.settings_registry._get_config_file_path', return_value=str(config_file)):
            with patch('shelfmark.core.settings_registry._ensure_config_dir'):
                with patch('shelfmark.config.security.load_config_file', return_value=config.copy()):
                    from shelfmark.config.security import _clear_builtin_credentials
                    result = _clear_builtin_credentials()

        assert result["success"] is True
        cleared_config = json.loads(config_file.read_text())
        assert "BUILTIN_USERNAME" not in cleared_config
        assert "BUILTIN_PASSWORD_HASH" not in cleared_config

    def test_clear_credentials_handles_errors(self):
        """Test that clearing credentials handles errors gracefully."""
        with patch('shelfmark.config.security.load_config_file', side_effect=Exception("Test error")):
            from shelfmark.config.security import _clear_builtin_credentials
            result = _clear_builtin_credentials()

        assert result["success"] is False
        assert "Test error" in result["message"]
