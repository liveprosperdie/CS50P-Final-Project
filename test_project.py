import pytest
from project import validate_input
from project import password_strength
from project import check_headers
from project import scan_ports


def test_input():
    assert validate_input("github.com","https://github.com","Shrey@7910")==("github.com","https://github.com", "Shrey@7910")
    with pytest.raises(SystemExit):
        validate_input("", "shrey","")
    assert validate_input("github.com","","Shrey@7910")
    assert validate_input("","https://github.com","Shrey")


def test_password_strength():
    assert password_strength("shrey")==(2,"Weak")
    assert password_strength("Shrey@1")==(5,"High")
    assert password_strength("")==None
    assert password_strength("shrey123")==(4,"Moderate")


def test_check_headers():
    assert isinstance(check_headers("https://github.com"),list)
    assert check_headers("")==None


def test_scan_ports():
    assert isinstance(scan_ports("github.com"),dict)
    assert scan_ports("")==None