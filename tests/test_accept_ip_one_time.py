import pytest
import subprocess
import time

# .pycache生成抑止
import sys
sys.dont_write_bytecode = True

# テスト用設定
ZONE = "test-zone"
IPV4_ADDRESS = "192.168.1.100"
IPV6_ADDRESS = "2001:db8::1"
INVALID_IP = "invalid-ip"
SERVICE = "http"
TIMEOUT = 10  # 秒

def run_command_with_args(args):
    """Subprocessを使用してコマンドを実行"""
    command = ["sudo", "./accept_ip_one_time.py"] + args
    return subprocess.run(command, capture_output=True, text=True)

@pytest.fixture(scope="session", autouse=True)
def precondition():
    """
    テスト前にdebug_list-rich-rulesが実行可能かどうかチェックする。
    実行できない場合はテストそのものを停止する。
    """
    result = run_command_with_args(["debug_list-rich-rules", "public"])
    if result.returncode != 0:
        print("")
        print("=== stdout ===")
        print(result.stdout)
        print("=== stderr ===")
        print(result.stderr)
        pytest.exit("debug_list-rich-rules error.")

@pytest.mark.parametrize("success_args", 
    [   
        ["allow", ZONE, SERVICE, IPV4_ADDRESS],
        ["allow", ZONE, SERVICE, IPV6_ADDRESS],
    ])
def test_success_args(success_args):
    """
    正常系テスト
    """
    zone = success_args[1]
    service = success_args[2]
    ipAddr = success_args[3]

    print(f"\nTest Parameter: ZONE={zone} SERVICE={service} ADDR={ipAddr}")

    # 追加しようとしているIPが既に登録されている場合は中止
    result = run_command_with_args(["debug_list-rich-rules", zone])
    assert ipAddr not in result.stdout, "追加しようとしているIPアドレスが既に存在。テスト中止。"

    # 普通に追加するパータン(timeoutなし)
    result = run_command_with_args(success_args)
    assert result.returncode == 0, f"Unexpected exit status {result.returncode}"

    # 追加後の確認
    result = run_command_with_args(["debug_list-rich-rules", zone])
    assert ipAddr in result.stdout, "ルールが追加されたことを確認できない"

    # 削除
    run_command_with_args(success_args+['--timeout=0'])
    assert result.returncode == 0, f"Unexpected exit status {result.returncode}"
    # 消えているはず
    result = run_command_with_args(["debug_list-rich-rules", zone])
    assert ipAddr not in result.stdout, "timeout=0でルール削除に失敗"

    # ここからTimeout付き試験
    # 1秒のTimeoutで追加
    result = run_command_with_args(success_args+["--timeout=1"])
    assert result.returncode == 0, f"Unexpected exit status {result.returncode}"
    # すぐに3秒のTimeoutで再追加。一旦ルールは削除されてTimeout=3のルールが加わるはず
    result = run_command_with_args(success_args+["--timeout=3"])
    assert result.returncode == 0, f"Unexpected exit status {result.returncode}"

    # 2秒待つ。
    time.sleep(2)

    # 3秒のTimeoutが生きてるはずなので、残ってるはず。
    result = run_command_with_args(["debug_list-rich-rules", zone])
    assert ipAddr in result.stdout, "IPアドレスが消えてしまっている"

    # 2秒待つ
    time.sleep(2)

    # 更に2秒待つと確実に消えるはず。
    result = run_command_with_args(["debug_list-rich-rules", zone])
    assert ipAddr not in result.stdout, "IPアドレスが意図せず残ってしまっている。"


@pytest.mark.parametrize("failed_args", 
    [   
        (["detarame", ZONE, SERVICE, IPV4_ADDRESS], 2),
        (["allow", "detarame", SERVICE, IPV4_ADDRESS], 2),
        (["allow", ZONE, "detarame", IPV4_ADDRESS], 2),
        (["allow", ZONE, SERVICE, "detarame"], 2),
    ])
def test_failed_args(failed_args):
    """
    異常系テスト
    """
    args = failed_args[0]
    expected_exit_status = failed_args[1]

    print(f"\nTest Parameter: ZONE={args[1]} SERVICE={args[2]} ADDR={args[3]} expected_exit_status={expected_exit_status}")

    result = run_command_with_args(args)
    print(f"=== stderr ===\n{result.stderr}")
    print(f"=== stdout ===\n{result.stdout}")

    assert result.returncode == expected_exit_status, f"Unexpected exit status {result.returncode}"
