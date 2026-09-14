import json

import pytest

from app.core import thresholds as th


@pytest.fixture(autouse=True)
def _reset(tmp_path, monkeypatch):
    monkeypatch.setattr(th, "_PATH", tmp_path / "thresholds.json")
    th.reset_thresholds()
    yield
    th.reset_thresholds()


def test_defaults_are_sane():
    t = th.get_thresholds()
    assert t.alert_min_risk == 4.0
    assert t.sev_critical > t.sev_high > t.sev_medium > t.sev_low


def test_set_persists_and_reloads():
    t = th.get_thresholds().model_copy(update={"alert_min_risk": 6.5})
    th.set_thresholds(t)
    assert th.get_thresholds().alert_min_risk == 6.5
    assert json.loads(th._PATH.read_text())["alert_min_risk"] == 6.5
    th._current = None
    assert th.get_thresholds().alert_min_risk == 6.5


def test_reset_restores_defaults():
    th.set_thresholds(th.get_thresholds().model_copy(update={"alert_min_risk": 9.0}))
    th.reset_thresholds()
    assert th.get_thresholds().alert_min_risk == 4.0
    assert not th._PATH.exists()


def test_validation_rejects_out_of_range():
    with pytest.raises(Exception):
        th.Thresholds(alert_min_risk=12)
