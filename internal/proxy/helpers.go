package proxy

import "fmt"

// RequireWhitelist returns the WhitelistManager for the adapter or an error
// if whitelist management is not supported. This eliminates scattered nil-checks.
func RequireWhitelist(adapter ProxyAdapter) (WhitelistManager, error) {
	wm := adapter.WhitelistManager()
	if wm == nil {
		return nil, fmt.Errorf("whitelist not supported for %s proxy", adapter.Type())
	}
	return wm, nil
}

// RequireCaptcha returns the CaptchaManager for the adapter or an error
// if captcha management is not supported.
func RequireCaptcha(adapter ProxyAdapter) (CaptchaManager, error) {
	cm := adapter.CaptchaManager()
	if cm == nil {
		return nil, fmt.Errorf("captcha not supported for %s proxy", adapter.Type())
	}
	return cm, nil
}

// RequireLogs returns the LogManager for the adapter or an error
// if log management is not supported.
func RequireLogs(adapter ProxyAdapter) (LogManager, error) {
	lm := adapter.LogManager()
	if lm == nil {
		return nil, fmt.Errorf("log management not supported for %s proxy", adapter.Type())
	}
	return lm, nil
}

// RequireBouncer returns the BouncerManager for the adapter or an error
// if bouncer management is not supported.
func RequireBouncer(adapter ProxyAdapter) (BouncerManager, error) {
	bm := adapter.BouncerManager()
	if bm == nil {
		return nil, fmt.Errorf("bouncer integration not supported for %s proxy", adapter.Type())
	}
	return bm, nil
}
