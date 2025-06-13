import re
from typing import List, Dict, Any, Optional, Union, Callable
from dataclasses import dataclass
from enum import Enum


class RuleType(Enum):
    """Enumeration of all supported Clash rule types"""
    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
    DOMAIN_REGEX = "DOMAIN-REGEX"
    GEOSITE = "GEOSITE"

    IP_CIDR = "IP-CIDR"
    IP_CIDR6 = "IP-CIDR6"
    IP_SUFFIX = "IP-SUFFIX"
    IP_ASN = "IP-ASN"
    GEOIP = "GEOIP"

    SRC_GEOIP = "SRC-GEOIP"
    SRC_IP_ASN = "SRC-IP-ASN"
    SRC_IP_CIDR = "SRC-IP-CIDR"
    SRC_IP_SUFFIX = "SRC-IP-SUFFIX"

    DST_PORT = "DST-PORT"
    SRC_PORT = "SRC-PORT"

    IN_PORT = "IN-PORT"
    IN_TYPE = "IN-TYPE"
    IN_USER = "IN-USER"
    IN_NAME = "IN-NAME"

    PROCESS_PATH = "PROCESS-PATH"
    PROCESS_PATH_REGEX = "PROCESS-PATH-REGEX"
    PROCESS_NAME = "PROCESS-NAME"
    PROCESS_NAME_REGEX = "PROCESS-NAME-REGEX"

    UID = "UID"
    NETWORK = "NETWORK"
    DSCP = "DSCP"

    RULE_SET = "RULE-SET"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    SUB_RULE = "SUB-RULE"

    MATCH = "MATCH"


class Action(Enum):
    """Enumeration of rule actions"""
    DIRECT = "DIRECT"
    REJECT = "REJECT"
    REJECT_DROP = "REJECT-DROP"
    PASS = "PASS"
    COMPATIBLE = "COMPATIBLE"


@dataclass
class ClashRule:
    """Represents a parsed Clash routing rule"""
    rule_type: RuleType
    payload: str
    action: Union[Action, str]  # Can be Action enum or custom proxy group name
    additional_params: Optional[List[str]] = None
    raw_rule: str = ""
    priority: int = 0

    def __post_init__(self):
        if self.additional_params is None:
            self.additional_params = []

    def condition_string(self) -> str:
        return f"{self.rule_type.value},{self.payload}"


@dataclass
class LogicRule:
    """Represents a logic rule (AND, OR, NOT)"""
    logic_type: RuleType
    conditions: List[Union[ClashRule, 'LogicRule']]
    action: Union[Action, str]
    raw_rule: str = ""
    priority: int = 0

    def condition_string(self) -> str:
        conditions_str = ','.join([f"({c.condition_string()})" for c in self.conditions])
        return f"{self.logic_type.value},({conditions_str})"


@dataclass
class MatchRule:
    """Represents a match rule"""
    action: Union[Action, str]
    raw_rule: str = ""
    priority: int = 0
    rule_type: RuleType = RuleType.MATCH

    @staticmethod
    def condition_string() -> str:
        return "MATCH"


class ClashRuleParser:
    """Parser for Clash routing rules"""

    def __init__(self):
        self.rules: List[Union[ClashRule, LogicRule, MatchRule]] = []

    @staticmethod
    def parse_rule_line(line: str) -> Optional[Union[ClashRule, LogicRule, MatchRule]]:
        """Parse a single rule line with enhanced error handling"""
        if not isinstance(line, str):
            print(f"Expected string but got {type(line)}: {line}")
            return None
            
        line = line.strip()
        if not line:
            return None

        try:
            if line.startswith(('AND,', 'OR,', 'NOT,')):
                return ClashRuleParser._parse_logic_rule(line)
            elif line.upper().startswith('MATCH,'):
                return ClashRuleParser._parse_match_rule(line)
            return ClashRuleParser._parse_regular_rule(line)
        except Exception as e:
            print(f"Error parsing rule '{line}': {e}")
            return None

    @staticmethod
    def parse_rule_dict(rule_dict: Union[Dict[str, Any], str]) -> Optional[Union[ClashRule, LogicRule, MatchRule]]:
        """Parse a rule from dictionary with type safety checks"""
        if isinstance(rule_dict, str):
            return ClashRuleParser.parse_rule_line(rule_dict)
            
        if not isinstance(rule_dict, dict):
            print(f"Expected dict but got {type(rule_dict)}: {rule_dict}")
            return None

        try:
            rule_type = rule_dict.get("type", "").upper()
            action = rule_dict.get("action", "")
            
            if not rule_type:
                print("Missing 'type' in rule dict")
                return None

            # Handle logic rules
            if rule_type in ('AND', 'OR', 'NOT'):
                conditions = rule_dict.get("conditions", [])
                if not isinstance(conditions, list):
                    print(f"Expected list of conditions but got {type(conditions)}")
                    return None
                    
                conditions_str = ""
                for cond in conditions:
                    if isinstance(cond, dict):
                        cond_type = cond.get("type", "")
                        cond_payload = cond.get("payload", "")
                        if cond_type and cond_payload:
                            conditions_str += f"({cond_type},{cond_payload})"
                    elif isinstance(cond, str):
                        conditions_str += cond
                
                if not conditions_str:
                    print("No valid conditions found")
                    return None
                    
                raw_rule = f"{rule_type},({conditions_str}),{action}"
                return ClashRuleParser._parse_logic_rule(raw_rule)

            # Handle MATCH rule
            elif rule_type == "MATCH":
                if not action:
                    print("Missing action for MATCH rule")
                    return None
                raw_rule = f"MATCH,{action}"
                return ClashRuleParser._parse_match_rule(raw_rule)

            # Handle regular rules
            else:
                payload = rule_dict.get("payload", "")
                if not payload:
                    print(f"Missing payload for rule type {rule_type}")
                    return None
                    
                additional_params = rule_dict.get("additional_params", [])
                if not isinstance(additional_params, list):
                    additional_params = []
                    
                raw_rule = f"{rule_type},{payload},{action}"
                if additional_params:
                    raw_rule += "," + ",".join(str(p) for p in additional_params)
                    
                return ClashRuleParser._parse_regular_rule(raw_rule)

        except Exception as e:
            print(f"Error parsing rule dict {rule_dict}: {e}")
            return None

    @staticmethod
    def _parse_match_rule(line: str) -> MatchRule:
        """Parse a MATCH rule with validation"""
        parts = [p.strip() for p in line.split(',') if p.strip()]
        if len(parts) != 2:
            raise ValueError(f"Invalid MATCH rule format: {line}")
            
        action = parts[1]
        try:
            action_enum = Action(action.upper())
            return MatchRule(action=action_enum, raw_rule=line)
        except ValueError:
            return MatchRule(action=action, raw_rule=line)

    @staticmethod
    def _parse_regular_rule(line: str) -> ClashRule:
        """Parse a regular rule with validation"""
        parts = [p.strip() for p in line.split(',') if p.strip()]
        if len(parts) < 3:
            raise ValueError(f"Invalid rule format (needs at least 3 parts): {line}")

        rule_type_str = parts[0].upper()
        payload = parts[1]
        action = parts[2]
        additional_params = parts[3:] if len(parts) > 3 else []

        try:
            rule_type = RuleType(rule_type_str)
        except ValueError as e:
            raise ValueError(f"Unknown rule type '{rule_type_str}' in rule: {line}") from e

        try:
            action_enum = Action(action.upper())
            final_action = action_enum
        except ValueError:
            final_action = action

        return ClashRule(
            rule_type=rule_type,
            payload=payload,
            action=final_action,
            additional_params=additional_params,
            raw_rule=line
        )

    @staticmethod
    def _parse_logic_rule(line: str) -> LogicRule:
        """Parse a logic rule (AND/OR/NOT) with validation"""
        # Improved regex to handle nested conditions
        match = re.match(r'^(AND|OR|NOT),\s*\((.+)\)\s*,\s*([^,]+)$', line.strip())
        if not match:
            raise ValueError(f"Invalid logic rule format: {line}")

        logic_type_str = match.group(1).upper()
        conditions_str = match.group(2).strip()
        action = match.group(3).strip()

        try:
            logic_type = RuleType(logic_type_str)
            conditions = ClashRuleParser._parse_logic_conditions(conditions_str)
            
            try:
                action_enum = Action(action.upper())
                final_action = action_enum
            except ValueError:
                final_action = action

            return LogicRule(
                logic_type=logic_type,
                conditions=conditions,
                action=final_action,
                raw_rule=line
            )
        except ValueError as e:
            raise ValueError(f"Invalid logic rule: {line}") from e

    @staticmethod
    def _parse_logic_conditions(conditions_str: str) -> List[ClashRule]:
        """Parse conditions within logic rules with support for nested structures"""
        conditions = []
        stack = []
        current = ""
        
        for char in conditions_str:
            if char == '(':
                if stack:
                    current += char
                stack.append(char)
            elif char == ')':
                if stack:
                    stack.pop()
                    if not stack:
                        try:
                            rule = ClashRuleParser._parse_single_condition(current)
                            if rule:
                                conditions.append(rule)
                        except ValueError as e:
                            print(f"Skipping invalid condition '{current}': {e}")
                        current = ""
                    else:
                        current += char
                else:
                    print(f"Unmatched closing parenthesis in conditions: {conditions_str}")
            else:
                if stack:
                    current += char
        
        return conditions

    @staticmethod
    def _parse_single_condition(condition_str: str) -> Optional[ClashRule]:
        """Parse a single condition from a logic rule"""
        parts = [p.strip() for p in condition_str.split(',', 1) if p.strip()]
        if len(parts) != 2:
            print(f"Invalid condition format: {condition_str}")
            return None
            
        rule_type_str, payload = parts
        try:
            rule_type = RuleType(rule_type_str.upper())
            return ClashRule(
                rule_type=rule_type,
                payload=payload,
                action="",  # Conditions don't have actions
                raw_rule=condition_str
            )
        except ValueError as e:
            print(f"Invalid rule type in condition: {rule_type_str}")
            return None

    # ... (其余方法保持不变，如 parse_rules, validate_rule, to_dict 等)