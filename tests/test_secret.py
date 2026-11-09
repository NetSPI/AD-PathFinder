import pytest

from modules.secret import Secret


def test_value_is_masked_but_exposable():
    s = Secret("hunter2")

    assert repr(s) == "Secret('***')"
    assert str(s) == "***"
    assert f"password={s}" == "password=***"
    assert s.expose() == "hunter2"
    assert s


@pytest.mark.parametrize("value", ["", None])
def test_empty_is_distinguishable_from_masked(value):
    s = Secret(value)

    assert repr(s) == "Secret('')"
    assert str(s) == ""
    assert s.expose() == ""
    assert not s


def test_equality_and_hash_follow_value():
    assert Secret("a") == Secret("a")
    assert hash(Secret("a")) == hash(Secret("a"))
    assert Secret("a") != Secret("b")
    assert Secret("a") != "a"
