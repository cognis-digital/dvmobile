from dvmobile.cli import main
from dvmobile.challenges import BY_ID


def test_challenges_listing(capsys):
    assert main(["challenges"]) == 0
    out = capsys.readouterr().out
    assert "idor-profile" in out
    assert "jwt-none" in out


def test_submit_correct_then_score(tmp_path, capsys):
    board = str(tmp_path / "s.json")
    rc = main(["submit", "config-leak", BY_ID["config-leak"].flag, "--board", board])
    assert rc == 0
    assert "correct" in capsys.readouterr().out
    assert main(["score", "--board", board]) == 0
    assert "1/4" in capsys.readouterr().out


def test_submit_wrong(tmp_path, capsys):
    rc = main(["submit", "idor-profile", "DVM{x}", "--board", str(tmp_path / "s.json")])
    assert rc == 1


def test_submit_unknown(tmp_path):
    assert main(["submit", "nope", "x", "--board", str(tmp_path / "s.json")]) == 2


def test_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()
