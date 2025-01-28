#!/usr/bin/python3
# -*- coding:utf-8 -*-

import dbus
import ipaddress
import argparse
import logging
import sys

# Exit Status
EXIT_SUCCESS           = 0
EXIT_GENERAL_ERROR     = 1
EXIT_INVALID_INPUT     = 2
EXIT_PERMISSION_ERROR  = 3
EXIT_RESOURCE_ERROR    = 4
EXIT_UNEXPECTED_ERROR  = 5

class AcceptIpOneTime:
    def __init__(self):

        # デフォルト値
        self.zone = ""
        self.service = ""
        self.timeout = 60
        self.bus = None

        # ログ設定
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] func=%(funcName)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger(__name__)

    # プログラムを終了させる必要があるエラーが発生した場合
    def die(self, errCode):
        self.logger.debug(f"Exit_status={errCode}")
        sys.exit(errCode)

    def __enter__(self):
        """コンテキストマネージャの開始時に呼ばれる"""
        self.logger.debug("Run __enter__")
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        """コンテキストマネージャの終了時に呼ばれる"""
        if self.bus:
            try:
                self.bus.close()
                self.logger.debug("DBus connection closed.")
            except AttributeError:
                self.logger.warning("DBus connection was already closed or not initialized.")
        else:
            pass

        # 例外を再スローしないためにFalseを返す
        return False

    def initDbus(self):
        """
        DBusに接続し、指定されたゾーンが存在するか確認
        返り値: True
        失敗したらプログラムを終了する
        """
        try:
            self.bus = dbus.SystemBus()
            self.firewalld = self.bus.get_object("org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
            self.interface = dbus.Interface(self.firewalld, dbus_interface="org.fedoraproject.FirewallD1.zone")

            # listServices向け
            self.interfaceFirewallD1 = dbus.Interface(self.firewalld, dbus_interface="org.fedoraproject.FirewallD1")

        except dbus.DBusException as e:
            self.logger.error(f"DBus error: {e}")
            self.die(EXIT_UNEXPECTED_ERROR)

        # 正常終了したらTrueを返す
        return True

    def checkRichRuleExists(self):
        """
        self.ruleのルールが存在しているかどうかをチェックする関数。
        存在していたらTrueを返し、存在していないならFalseを返す
        通常1つしかヒットしないので、1 or 0 以外の結果になったらエラーを起こして停止する。
        """
        numOfRules = self.interface.queryRichRule(self.zone, self.rule)
        if numOfRules==1:
            return(True)
        elif numOfRules==0:
            return(False)
        else:
            self.logger.error(f"Multiple rich rule matched: {self.rule}")
            self.die(EXIT_UNEXPECTED_ERROR)

    def preCheckAndRemoveSameRule(self):
        """
        登録する前にRichRuleが存在していないかどうかチェックし、
        存在していたら削除する
        """
        if self.checkRichRuleExists():
            # RichRuleが存在していた場合、削除してから追加する
            self.logger.debug("The rule already exists. Removing...")
            self.interface.removeRichRule(self.zone, self.rule)

            # 削除されたか確認。残っていたら異常。
            if self.checkRichRuleExists():
                self.logger.error(f"RichRule Delete failed: {self.rule}")
                self.die(EXIT_UNEXPECTED_ERROR)

            self.logger.debug("Rule removed.")

    def accept(self):
        """
        指定されたIPアドレスをfirewalldに許可する
        ※この関数は終了時にrun_clitを経由してmainに戻る為、return時はEXIT_STATUSを指定してください※
        """
        # ルールを作成
        self.rule = f'rule family="{self.ip_type}" source address="{self.ipAddress}" service name="{self.service}" accept'

        # 追加前に既にルールが存在しているかどうかをチェック
        self.logger.debug(f"checkSameRule: START")
        self.preCheckAndRemoveSameRule()
        self.logger.debug(f"checkSameRule: END")

        # timeout=0の場合、削除のみ実施してRichRuleの追加は実行しない
        # 削除は上記で実施しているので、これ以上やることはない
        if self.timeout==0:
            self.logger.debug("timeout=0, no added, delete only")
            return(EXIT_SUCCESS)

        try:
            # RichRuleを実際に追加する。
            self.logger.debug("runAddFirewalld: START")
            self.interface.addRichRule(self.zone, self.rule, self.timeout)
            self.logger.debug("runAddFirewalld: END")

            # ちゃんとルールが入ったかチェック          
            self.logger.debug("checkAddedRule: START")
            if not self.checkRichRuleExists():
                self.logger.error(f"Failed add rule: {self.rule}")
                self.die(EXIT_UNEXPECTED_ERROR)
            self.logger.debug("checkAddedRule: END")
            self.logger.debug("Completed!")
            return (EXIT_SUCCESS)

        except dbus.DBusException as e:
            self.logger.error("accept error: "+str(e))
            self.die(EXIT_UNEXPECTED_ERROR)

    def checkValues_ipAddr(self):
        """
        引数が正しくIPアドレスになっているかどうかをチェックします。
        また、IPv4なのか、IPv6なのかも判定し、self.ip_typeに代入します。
        IPアドレスではない物が指定された場合はプログラムを終了します。
        """
        try:
            ip = ipaddress.ip_address(self.ipAddress)
            self.ip_type = 'ipv4' if isinstance(ip, ipaddress.IPv4Address) else 'ipv6'
        except ValueError as e:
            self.logger.error(f"Invalid IP format: {self.ipAddress}. Error: {e}")
            self.die(EXIT_INVALID_INPUT)

    def checkValues_zone(self):
        """
        ゾーンが存在しているかどうかを確認する
        """
        if self.zone not in self.interface.getZones():
            self.logger.error("DBus zone not found.")
            self.die(EXIT_INVALID_INPUT)

    def checkValues_service(self):
        """
        指定されたサービスが存在しているか確かめる。
        存在していない場合はエラーとする。
        """
        if  self.service not in self.interfaceFirewallD1.listServices():
            self.logger.error("Undefined service: "+str(self.service))
            self.die(EXIT_INVALID_INPUT)

    def main(self):
        """
        メイン関数
        """
        # initDBus	
        # DBusの初期化を実行する
        self.logger.debug(f"initDbus: START")
        self.initDbus()
        self.logger.debug(f"initDbus: END")
        
        # ここから各パラメーターを実行していく
        self.logger.debug(f"checkValues: ipAddr...")
        self.checkValues_ipAddr()

        self.logger.debug(f"checkValues: zone...")
        self.checkValues_zone()
        
        self.logger.debug(f"checkValues: service...")
        self.checkValues_service()
        
        self.logger.debug(f"checkValues: END")

        self.accept()

    def run_cli(self):
        """
        コマンドライン引数を処理してメイン関数に渡す。
        ※この関数は終了時にmainに戻る為、return時はEXIT_STATUSを指定してください※
        """

        self.logger.debug(f"checkSyntax: START cmd-line: {sys.argv}")

        parser = argparse.ArgumentParser(description="Manage IP access and debug operations for firewalld")
        subparsers = parser.add_subparsers(dest="subcommand", required=True)

        # サブコマンド: allow
        allow_parser = subparsers.add_parser("allow", help="Allow access for a specific IP")
        allow_parser.add_argument("zone", help="FirewallD zone")
        allow_parser.add_argument("service", help="Service to allow")
        allow_parser.add_argument("ipAddress", help="IP address to allow")
        allow_parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds (default: 300)")

        # サブコマンド: debug_list-rich-rules
        debug_parser = subparsers.add_parser("debug_list-rich-rules", help="List rich rules for a specified zone")
        debug_parser.add_argument("zone", help="FirewallD zone")

        # ※引数に不足がある場合、ここでエラーになる。(exit_status=2)
        args = parser.parse_args()

        self.logger.debug(f"checkSyntax: END")

        if args.subcommand == "allow":

            # サブコマンド allow
            # パラメーターは全てクラス側で指定する
            self.zone       = args.zone
            self.service    = args.service
            self.timeout    = args.timeout
            self.ipAddress  = args.ipAddress

            # 次の関数に渡す
            self.main()

            # 正常終了した場合ここまで残る。異常の場合は終了する
            return(EXIT_SUCCESS)

        elif args.subcommand == "debug_list-rich-rules":
            # サブコマンド： debug_list-rich-rules
            self.zone = args.zone
            return(self.debug_list_rich_rules())
        else:
            # ここは普通来ない。
            parser.print_help()
            return(EXIT_UNEXPECTED_ERROR)

    def debug_list_rich_rules(self):
        """
        テスト用：指定されたゾーンのリッチルールを表示
        ※この関数は終了時にrun_clitを経由してmainに戻る為、return時はEXIT_STATUSを指定してください※
        """
        try:
            # Dbusへ接続
            self.initDbus()

            # RichRuleを一覧
            rules = self.interface.getRichRules(self.zone)

            # ルールがない場合はemptyと表示する
            if rules:
                for rule in rules:
                    print(rule)
            else:
                print(f"No rich rules are configured for the zone '{self.zone}'.")

        except dbus.DBusException as e:
            self.logger.error(f"Failed to list rich rules: {str(e)}")
            self.die(EXIT_UNEXPECTED_ERROR)
            
        return(EXIT_SUCCESS)


if __name__ == "__main__":
    with AcceptIpOneTime() as t:
        sys.exit(t.run_cli())
