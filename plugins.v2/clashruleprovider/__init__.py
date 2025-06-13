import hashlib
import re
import time
from datetime import datetime, timedelta
from typing import Any, Optional, List, Dict, Tuple, Union

import pytz
import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Body, Response

from app.core.config import settings
from app.core.event import eventmanager
from app.log import logger
from app.plugins import _PluginBase
from app.plugins.clashruleprovider.clash_rule_parser import Action, RuleType, ClashRule, MatchRule, LogicRule
from app.plugins.clashruleprovider.clash_rule_parser import ClashRuleParser
from app.schemas.types import EventType
from app.utils.http import RequestUtils


class ClashRuleProvider(_PluginBase):
    # 插件名称
    plugin_name = "Clash Rule Provider"
    # 插件描述
    plugin_desc = "随时为Clash添加一些额外的规则。"
    # 插件图标
    plugin_icon = ("https://raw.githubusercontent.com/wumode/MoviePilot-Plugins/"
                   "refs/heads/imdbsource_assets/icons/Mihomo_Meta_A.png")
    # 插件版本
    plugin_version = "0.1.2"
    # 插件作者
    plugin_author = "wumode"
    # 作者主页
    author_url = "https://github.com/wumode"
    # 插件配置项ID前缀
    plugin_config_prefix = "clashruleprovider_"
    # 加载顺序
    plugin_order = 99
    # 可使用的用户级别
    auth_level = 1

    # 插件配置
    _enabled = False
    _proxy = False
    _notify = False
    _sub_links = []
    _clash_dashboard_url = None
    _clash_dashboard_secret = None
    _movie_pilot_url = None
    _cron = ''
    _timeout = 10
    _retry_times = 3
    _filter_keywords = []
    _auto_update_subscriptions = True
    _ruleset_prefix = '📂<-'

    # 插件数据
    _clash_config = None
    _top_rules: List[str] = []
    _ruleset_rules: List[str] = []
    _rule_provider: Dict[str, Any] = {}
    _subscription_info = {}
    _ruleset_names: Dict[str, str] = {}

    # 内部组件
    _clash_rule_parser = None
    _ruleset_rule_parser = None
    _scheduler: Optional[BackgroundScheduler] = None

    def init_plugin(self, config: dict = None):
        """初始化插件"""
        try:
            # 加载持久化数据
            self._clash_config = self.get_data("clash_config") or {}
            self._ruleset_rules = self.get_data("ruleset_rules") or []
            self._top_rules = self.get_data("top_rules") or []
            self._subscription_info = self.get_data("subscription_info") or {
                "download": 0, "upload": 0, "total": 0, "expire": 0, "last_update": 0
            }
            self._rule_provider = self.get_data("rule_provider") or {}
            self._ruleset_names = self.get_data("ruleset_names") or {}

            # 更新配置
            if config and isinstance(config, dict):  # 确保config是字典
                self._enabled = config.get("enabled", False)
                self._proxy = config.get("proxy", False)
                self._notify = config.get("notify", False)
                self._sub_links = config.get("sub_links", [])
                self._clash_dashboard_url = config.get("clash_dashboard_url")
                self._clash_dashboard_secret = config.get("clash_dashboard_secret")
                mp_url = config.get("movie_pilot_url", "")
                self._movie_pilot_url = mp_url.rstrip('/') if mp_url else ""
                self._cron = config.get("cron_string", "")
                self._timeout = int(config.get("timeout", 10))
                self._retry_times = int(config.get("retry_times", 3))
                self._filter_keywords = config.get("filter_keywords", [])
                self._ruleset_prefix = config.get("ruleset_prefix", "Custom_")
                self._auto_update_subscriptions = config.get("auto_update_subscriptions", True)

            # 初始化解析器
            self._clash_rule_parser = ClashRuleParser()
            self._ruleset_rule_parser = ClashRuleParser()
            self.__parse_config()

            # 启动调度器
            if self._enabled:
                self._scheduler = BackgroundScheduler(timezone=settings.TZ)
                self._scheduler.start()

        except Exception as e:
            logger.error(f"插件初始化失败: {str(e)}")
            self._enabled = False

    def update_subscription_service(self) -> bool:
        """更新订阅数据"""
        if not self._sub_links or not self._enabled:
            return False

        try:
            url = self._sub_links[0]
            ret = RequestUtils(
                accept_type="text/html",
                proxies=settings.PROXY if self._proxy else None
            ).get_res(url)
            
            if not ret or not ret.content:
                logger.error("获取订阅内容失败或内容为空")
                return False

            # 修复点：确保正确处理响应内容
            try:
                content = ret.content
                if isinstance(content, bytes):
                    content = content.decode('utf-8')
                
                # 确保内容是有效的YAML
                rs = yaml.safe_load(content)
                if not rs or not isinstance(rs, dict):  # 确保解析结果是字典
                    logger.error("订阅内容解析失败或不是有效的YAML字典")
                    return False
                
                self._clash_config = self.__remove_nodes_by_keywords(rs)
            except (yaml.YAMLError, UnicodeDecodeError) as e:
                logger.error(f"解析订阅内容出错: {str(e)}")
                return False

            # 更新订阅信息
            if 'Subscription-Userinfo' in ret.headers:
                try:
                    matches = re.findall(r'(\w+)=(\d+)', ret.headers['Subscription-Userinfo'])
                    variables = {key: int(value) for key, value in matches}
                    self._subscription_info.update({
                        'download': variables.get('download', 0),
                        'upload': variables.get('upload', 0),
                        'total': variables.get('total', 0),
                        'expire': variables.get('expire', 0)
                    })
                except Exception as e:
                    logger.error(f"解析订阅信息失败: {str(e)}")

            self._subscription_info["last_update"] = int(time.time())
            self.save_data('subscription_info', self._subscription_info)
            self.save_data('clash_config', self._clash_config)
            return True

        except Exception as e:
            logger.error(f"订阅更新失败: {str(e)}")
            return False

    def __remove_nodes_by_keywords(self, clash_config: Dict[str, Any]) -> Dict[str, Any]:
        """根据关键词过滤节点"""
        if not isinstance(clash_config, dict):
            logger.error("配置不是字典类型")
            return {}
            
        try:
            removed_proxies = []
            proxies = []
            
            # 确保proxies存在且是列表
            config_proxies = clash_config.get("proxies", [])
            if not isinstance(config_proxies, list):
                logger.warning("proxies不是列表类型")
                config_proxies = []
            
            for proxy in config_proxies:
                if not isinstance(proxy, dict):
                    continue
                    
                proxy_name = proxy.get("name", "")
                if not isinstance(proxy_name, str):
                    continue
                    
                has_keywords = any(
                    keyword in proxy_name 
                    for keyword in self._filter_keywords 
                    if isinstance(keyword, str)
                )
                
                if has_keywords:
                    removed_proxies.append(proxy_name)
                else:
                    proxies.append(proxy)
            
            if proxies:
                clash_config["proxies"] = proxies
            else:
                logger.warning("关键词过滤后无可用节点，跳过过滤")
                removed_proxies = []
            
            # 处理proxy-groups
            if "proxy-groups" in clash_config:
                proxy_groups = clash_config["proxy-groups"]
                if not isinstance(proxy_groups, list):
                    proxy_groups = []
                
                for group in proxy_groups:
                    if isinstance(group, dict) and "proxies" in group:
                        group_proxies = group["proxies"]
                        if isinstance(group_proxies, list):
                            group["proxies"] = [
                                p for p in group_proxies 
                                if isinstance(p, str) and p not in removed_proxies
                            ]
                
                clash_config["proxy-groups"] = [
                    g for g in proxy_groups 
                    if isinstance(g, dict) and g.get("proxies", [])
                ]
            
            return clash_config
            
        except Exception as e:
            logger.error(f"过滤节点出错: {str(e)}")
            return clash_config

    # ... 其他方法保持不变，但确保所有字典访问都使用.get()方法