"""Test for Sagemcom F@st client."""

from sagemcom_api import __version__


def test_version():
    """Test if version number is 1.0.0."""
    assert __version__ == "1.0.0"
