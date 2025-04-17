import pytest
from src.facade.ServerSecurityFacade import ServerSecurityFacade

def test_service_analyzer():
    # Arrange
    analyzer = ServerSecurityFacade()
    hostname = "www.google.com"

    # Act
    report = analyzer.analyze_server(hostname)

    # Assert
    assert report is not None
    assert isinstance(report, dict)

