from pathlib import Path

from chatcli.skills import rank_skills


def test_tencent_remote_analysis_skill_matches_remote_dynamic_requests():
    workspace = str(Path(__file__).resolve().parents[1])

    matches = rank_skills("腾讯云 remote_guest 动态分析 网络流量 tshark", workspace)

    assert matches
    names = [skill.name for _, skill in matches]
    assert "tencent-remote-analysis" in names
