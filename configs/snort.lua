HOME_NET = '10.0.1.0/24'
EXTERNAL_NET = 'any'
RULE_PATH = '/etc/snort/rules'
SO_RULE_PATH = '/etc/snort/so_rules'
LISTS_PATH = '/etc/snort/lists'

alert_json = {
    file = true,
    limit = 100,
    filename = '/var/log/snort/alert_json.txt'
}

ips = {
    rules = [[
        include /etc/snort/rules/local.rules
    ]]
}
