package engine

func CheckPayload(payload []byte, rules []CompiledRule) (string, string, string) {
	if payload == nil {
		return "", "", ""
	}
	for _, rule := range rules {
		if rule.CompiledExp.Match(payload) {
			return rule.Nom, rule.Description, rule.Severity
		}
	}
	return "", "", ""
}
