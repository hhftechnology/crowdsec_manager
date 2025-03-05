#!/bin/bash

# Function to set up captcha protection
setup_captcha() {
    print_header "SETTING UP CAPTCHA PROTECTION"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot set up captcha."
        return 1
    fi
    
    if ! check_container "traefik"; then
        print_error "Traefik container is not running. Cannot set up captcha."
        return 1
    fi
    
    echo -e "${YELLOW}This will set up Cloudflare Turnstile captcha protection in CrowdSec.${NC}"
    
    if ! confirm_action "Do you want to proceed?"; then
        echo -e "${YELLOW}Captcha setup canceled.${NC}"
        return 0
    fi
    
    DYNAMIC_CONFIG_PATH="./config/traefik/dynamic_config.yml"
    
    if [[ ! -f "$DYNAMIC_CONFIG_PATH" ]]; then
        print_error "Traefik dynamic_config.yml not found at $DYNAMIC_CONFIG_PATH"
        return 1
    fi
    
    if grep -q "captchaProvider\|captchaSiteKey\|captchaSecretKey" "$DYNAMIC_CONFIG_PATH"; then
        print_warning "Captcha appears to be already configured in Traefik middleware"
        if ! confirm_action "Do you want to overwrite the existing captcha configuration?"; then
            echo -e "${YELLOW}Keeping existing captcha configuration. Returning to menu.${NC}"
            return 0
        fi
        echo -e "${YELLOW}Proceeding to update existing captcha configuration...${NC}"
    fi
    
    trap 'echo -e "\n${YELLOW}Captcha setup cancelled. Returning to menu...${NC}"; return 1' SIGINT
    
    echo -ne "${YELLOW}Enter your Cloudflare Turnstile Site Key:${NC} "
    read -r SITE_KEY || return 1
    
    if [[ -z "$SITE_KEY" ]]; then
        print_error "Site key cannot be empty."
        trap handle_sigint SIGINT
        return 1
    fi
    
    echo -ne "${YELLOW}Enter your Cloudflare Turnstile Secret Key:${NC} "
    read -r SECRET_KEY || return 1
    
    if [[ -z "$SECRET_KEY" ]]; then
        print_error "Secret key cannot be empty."
        trap handle_sigint SIGINT
        return 1
    fi
    
    trap handle_sigint SIGINT
    
    echo -e "${YELLOW}Creating captcha remediation profile...${NC}"
    
    PROFILES_PATH="./config/crowdsec/profiles.yaml"
    if [[ ! -f "$PROFILES_PATH" ]]; then
        cat > "$PROFILES_PATH" << EOF
name: captcha_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"
decisions:
 - type: captcha
   duration: 4h
on_success: break

---
name: default_ip_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
on_success: break
EOF
        print_success "Created new profiles.yaml with captcha configuration"
    else
        if grep -q "captcha_remediation" "$PROFILES_PATH"; then
            print_warning "Captcha profile already exists in profiles.yaml"
        else
            TMP_PROFILE="${TEMP_DIR}/captcha_profile.yaml"
            TMP_NEW_PROFILES="${TEMP_DIR}/new_profiles.yaml"
            
            cat > "$TMP_PROFILE" << EOF
name: captcha_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"
decisions:
 - type: captcha
   duration: 4h
on_success: break

---
EOF
            cat "$TMP_PROFILE" "$PROFILES_PATH" > "$TMP_NEW_PROFILES"
            
            if ! mv "$TMP_NEW_PROFILES" "$PROFILES_PATH"; then
                print_error "Failed to update profiles.yaml"
                return 1
            fi
            
            print_success "Added captcha profile to existing profiles.yaml"
        fi
    fi
    
    TRAEFIK_CONF_DIR="./config/traefik/conf"
    mkdir -p "$TRAEFIK_CONF_DIR"
    
    CAPTCHA_HTML_PATH="$TRAEFIK_CONF_DIR/captcha.html"
    echo -e "${YELLOW}Creating captcha HTML template...${NC}"
    
    cat > "$CAPTCHA_HTML_PATH" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <title>CrowdSec Captcha</title>
  <meta content="text/html; charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    *,:after,:before{border:0 solid #e5e7eb;box-sizing:border-box}:after,:before{--tw-content:""}html{-webkit-text-size-adjust:100%;font-feature-settings:normal;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4}body{line-height:inherit;margin:0}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}*,::backdrop,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x:;--tw-pan-y:;--tw-pinch-zoom:;--tw-scroll-snap-strictness:proximity;--tw-ordinal:;--tw-slashed-zero:;--tw-numeric-figure:;--tw-numeric-spacing:;--tw-numeric-fraction:;--tw-ring-inset:;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:#3b82f680;--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur:;--tw-brightness:;--tw-contrast:;--tw-grayscale:;--tw-hue-rotate:;--tw-invert:;--tw-saturate:;--tw-sepia:;--tw-drop-shadow:;--tw-backdrop-blur:;--tw-backdrop-brightness:;--tw-backdrop-contrast:;--tw-backdrop-grayscale:;--tw-backdrop-hue-rotate:;--tw-backdrop-invert:;--tw-backdrop-opacity:;--tw-backdrop-saturate:;--tw-backdrop-sepia:}.flex{display:flex}.flex-wrap{flex-wrap:wrap}.inline-flex{display:inline-flex}.h-24{height:6rem}.h-6{height:1.5rem}.h-full{height:100%}.h-screen{height:100vh}.text-center{text-align:center}.w-24{width:6rem}.w-6{width:1.5rem}.w-full{width:100%}.w-screen{width:100vw}.my-3{margin-top:0.75rem;margin-bottom:0.75rem}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.space-y-1>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(.25rem*var(--tw-space-y-reverse));margin-top:calc(.25rem*(1 - var(--tw-space-y-reverse)))}.space-y-4>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(1rem*var(--tw-space-y-reverse));margin-top:calc(1rem*(1 - var(--tw-space-y-reverse)))}.rounded-xl{border-radius:.75rem}.border-2{border-width:2px}.border-black{--tw-border-opacity:1;border-color:rgb(0 0 0/var(--tw-border-opacity))}.p-4{padding:1rem}.px-4{padding-left:1rem;padding-right:1rem}.py-2{padding-bottom:.5rem;padding-top:.5rem}.text-2xl{font-size:1.5rem;line-height:2rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.font-bold{font-weight:700}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity))}@media (min-width:640px){.sm\:w-2\/3{width:66.666667%}}@media (min-width:768px){.md\:flex-row{flex-direction:row}}@media (min-width:1024px){.lg\:w-1\/2{width:50%}.lg\:text-3xl{font-size:1.875rem;line-height:2.25rem}.lg\:text-xl{font-size:1.25rem;line-height:1.75rem}}@media (min-width:1280px){.xl\:text-4xl{font-size:2.25rem;line-height:2.5rem}}
  </style>
  <script src="{{ .FrontendJS }}" async defer></script>
</head>
<body class="h-screen w-screen p-4">
  <div class="h-full w-full flex flex-col justify-center items-center">
    <div class="border-2 border-black rounded-xl p-4 text-center w-full sm:w-2/3 lg:w-1/2">
      <div class="flex flex-col items-center space-y-4">
        <svg fill="black" class="h-24 w-24" aria-hidden="true" focusable="false" data-prefix="fas" data-icon="exclamation-triangle" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" class="warning"><path d="M569.517 440.013C587.975 472.007 564.806 512 527.94 512H48.054c-36.937 0-59.999-40.055-41.577-71.987L246.423 23.985c18.467-32.009 64.72-31.951 83.154 0l239.94 416.028zM288 354c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"></path></svg>
        <h1 class="text-2xl lg:text-3xl xl:text-4xl">CrowdSec Captcha</h1>
      </div>
      <form action="" method="POST" class="flex flex-col space-y-1" id="captcha-form">
        <div id="captcha" class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback"></div>
      </form>
      <div class="flex justify-center flex-wrap">
        <p class="my-3">This security check has been powered by</p>
        <a href="https://crowdsec.net/" target="_blank" rel="noopener" class="inline-flex flex-col items-center">
          <svg fill="black" width="33.92" height="33.76" viewBox="0 0 254.4 253.2"><defs><clipPath id="a"><path d="M0 52h84v201.2H0zm0 0"/></clipPath><clipPath id="b"><path d="M170 52h84.4v201.2H170zm0 0"/></clipPath></defs><path d="M59.3 128.4c1.4 2.3 2.5 4.6 3.4 7-1-4.1-2.3-8.1-4.3-12-3.1-6-7.8-5.8-10.7 0-2 4-3.2 8-4.3 12.1 1-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M207.8 128.4a42.9 42.9 0 013.4 7c-1-4.1-2.3-8.1-4.3-12-3.2-6-7.8-5.8-10.7 0-2 4-3.3 8-4.3 12.1.9-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M134.6 92.9c2 3.5 3.6 7 4.8 10.7-1.3-5.4-3-10.6-5.6-15.7-4-7.5-9.7-7.2-13.3 0a75.4 75.4 0 00-5.6 16c1.2-3.8 2.7-7.4 4.7-11 4.1-7.2 10.6-7.5 15 0M43.8 136.8c.9 4.6 3.7 8.3 7.3 9.2 0 2.7 0 5.5.2 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4M192.4 136.8c.8 4.6 3.7 8.3 7.2 9.2 0 2.7 0 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3.9 2.2 1.2 0 .6-3 .7-6.3 1-9.6.2-2.7.3-5.5.2-8.2 3.6-1 6.4-4.6 7.3-9.2a17.8 17.8 0 01-9.1 2.4c-3.4 0-6.6-1-9.1-2.4M138.3 104.6c-3.1 1.9-7 3-11.3 3-4.3 0-8.2-1.1-11.3-3 1 5.8 4.5 10.3 9 11.5 0 3.4 0 6.8.3 10.2.4 4.1.5 8.2 1.2 12 .4 2.9 1.2 2.7 1.6 0 .7-3.8.8-7.9 1.2-12 .3-3.4.3-6.8.3-10.2 4.5-1.2 8-5.7 9-11.5"/><path d="M51 146c0 2.7.1 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4.9 4.6 3.7 8.3 7.3 9.2M143.9 105c-1.9-.4-3.5-1.2-4.9-2.3 1.4 5.6 2.5 11.3 4 17 1.2 5 2 10 2.4 15 .6 7.8-4.5 14.5-10.9 14.5h-15c-6.4 0-11.5-6.7-11-14.5.5-5 1.3-10 2.6-15 1.3-5.3 2.3-10.5 3.6-15.7-2.2 1.2-4.8 1.9-7.7 2-4.7.1-9.4-.3-14-1-4-.4-6.7-3-8-6.7-1.3-3.4-2-7-3.3-10.4-.5-1.5-1.6-2.8-2.4-4.2-.4-.6-.8-1.2-.9-1.8v-7.8a77 77 0 0124.5-3c6.1 0 12 1 17.8 3.2 4.7 1.7 9.7 1.8 14.4 0 9-3.4 18.2-3.8 27.5-3 4.9.5 9.8 1.6 14.8 2.4v8.2c0 .6-.3 1.5-.7 1.7-2 .9-2.2 2.7-2.7 4.5-.9 3.2-1.8 6.4-2.9 9.5a11 11 0 01-8.8 7.7 40.6 40.6 0 01-18.4-.2m29.4 80.6c-3.2-26.8-6.4-50-8.9-60.7a14.3 14.3 0 0014.1-14h.4a9 9 0 005.6-16.5 14.3 14.3 0 00-3.7-27.2 9 9 0 00-6.9-14.6c2.4-1.1 4.5-3 5.8-5 3.4-5.3 4-29-8-44.4-5-6.3-9.8-2.5-10 1.8-1 13.2-1.1 23-4.5 34.3a9 9 0 00-16-4.1 14.3 14.3 0 00-28.4 0 9 9 0 00-16 4.1c-3.4-11.2-3.5-21.1-4.4-34.3-.3-4.3-5.2-8-10-1.8-12 15.3-11.5 39-8.1 44.4 1.3 2 3.4 3.9 5.8 5a9 9 0 00-7 14.6 14.3 14.3 0 00-3.6 27.2A9 9 0 0075 111h.5a14.5 14.5 0 0014.3 14c-4 17.2-10 66.3-15 111.3l-1.3 13.4a1656.4 1656.4 0 01106.6 0l-1.4-12.7-5.4-51.3"/><g clip-path="url(#a)"><path d="M83.5 136.6l-2.3.7c-5 1-9.8 1-14.8-.2-1.4-.3-2.7-1-3.8-1.9l3.1 13.7c1 4 1.7 8 2 12 .5 6.3-3.6 11.6-8.7 11.6H46.9c-5.1 0-9.2-5.3-8.7-11.6.3-4 1-8 2-12 1-4.2 1.8-8.5 2.9-12.6-1.8 1-3.9 1.5-6.3 1.6a71 71 0 01-11.1-.7 7.7 7.7 0 01-6.5-5.5c-1-2.7-1.6-5.6-2.6-8.3-.4-1.2-1.3-2.3-2-3.4-.2-.4-.6-1-.6-1.4v-6.3c6.4-2 13-2.6 19.6-2.5 4.9.1 9.6 1 14.2 2.6 3.9 1.4 7.9 1.5 11.7 0 1.8-.7 3.6-1.2 5.5-1.6a13 13 0 01-1.6-15.5A18.3 18.3 0 0159 73.1a11.5 11.5 0 00-17.4 8.1 7.2 7.2 0 00-12.9 3.3c-2.7-9-2.8-17-3.6-27.5-.2-3.4-4-6.5-8-1.4C7.5 67.8 7.9 86.9 10.6 91c1.1 1.7 2.8 3.1 4.7 4a7.2 7.2 0 00-5.6 11.7 11.5 11.5 0 00-2.9 21.9 7.2 7.2 0 004.5 13.2h.3c0 .6 0 1.1.2 1.7.9 5.4 5.6 9.5 11.3 9.5A1177.2 1177.2 0 0010 253.2c18.1-1.5 38.1-2.6 59.5-3.4.4-4.6.8-9.3 1.4-14 1.2-11.6 3.3-30.5 5.7-49.7 2.2-18 4.7-36.3 7-49.5"/></g><g clip-path="url(#b)"><path d="M254.4 118.2c0-5.8-4.2-10.5-9.7-11.4a7.2 7.2 0 00-5.6-11.7c2-.9 3.6-2.3 4.7-4 2.7-4.2 3.1-23.3-6.5-35.5-4-5.1-7.8-2-8 1.4-.8 10.5-.9 18.5-3.6 27.5a7.2 7.2 0 00-12.8-3.3 11.5 11.5 0 00-17.8-7.9 18.4 18.4 0 01-4.5 22 13 13 0 01-1.3 15.2c2.4.5 4.8 1 7.1 2 3.8 1.3 7.8 1.4 11.6 0 7.2-2.8 14.6-3 22-2.4 4 .4 7.9 1.2 12 1.9l-.1 6.6c0 .5-.2 1.2-.5 1.3-1.7.7-1.8 2.2-2.2 3.7l-2.3 7.6a8.8 8.8 0 01-7 6.1c-5 1-10 1-14.9-.2-1.5-.3-2.8-1-3.9-1.9 1.2 4.5 2 9.1 3.2 13.7 1 4 1.6 8 2 12 .4 6.3-3.6 11.6-8.8 11.6h-12c-5.2 0-9.3-5.3-8.8-11.6.4-4 1-8 2-12 1-4.2 1.9-8.5 3-12.6-1.8 1-4 1.5-6.3 1.6-3.7 0-7.5-.3-11.2-.7a7.7 7.7 0 01-3.7-1.5c3.1 18.4 7.1 51.2 12.5 100.9l.6 5.3.8 7.9c21.4.7 41.5 1.9 59.7 3.4L243 243l-4.4-41.2a606 606 0 00-7-48.7 11.5 11.5 0 0011.2-11.2h.4a7.2 7.2 0 004.4-13.2c4-1.8 6.8-5.8 6.8-10.5"/></g><path d="M180 249.6h.4a6946 6946 0 00-7.1-63.9l5.4 51.3 1.4 12.6M164.4 125c2.5 10.7 5.7 33.9 8.9 60.7a570.9 570.9 0 00-8.9-60.7M74.8 236.3l-1.4 13.4 1.4-13.4"/>
          </svg>
          <span>CrowdSec</span>
        </a>
      </div>
    </div>
  </div>
  <script>
    function captchaCallback() {
      setTimeout(() => document.querySelector('#captcha-form').submit(), 500);
    }
  </script>
</body>
</html>
EOF
    
    print_success "Created captcha.html template"
    
    echo -e "${YELLOW}Updating Traefik middleware configuration...${NC}"
    
    BACKUP_CONFIG="${DYNAMIC_CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    if ! cp "$DYNAMIC_CONFIG_PATH" "$BACKUP_CONFIG"; then
        print_error "Failed to create backup of dynamic_config.yml"
        return 1
    fi
    
    print_success "Created backup of dynamic_config.yml at $BACKUP_CONFIG"
    
    if grep -q "crowdsec:" "$DYNAMIC_CONFIG_PATH"; then
        TEMP_CONFIG="${TEMP_DIR}/dynamic_config.yml.tmp"
        
        sed '/captchaProvider\|captchaSiteKey\|captchaSecretKey\|captchaGracePeriodSeconds\|captchaHTMLFilePath/d' "$DYNAMIC_CONFIG_PATH" > "$TEMP_CONFIG"
        
        sed -i "/crowdsec:/,/enabled: true/ s/enabled: true/enabled: true\n          captchaProvider: turnstile\n          captchaSiteKey: \"$SITE_KEY\"\n          captchaSecretKey: \"$SECRET_KEY\"\n          captchaGracePeriodSeconds: 1800\n          captchaHTMLFilePath: \"\/etc\/traefik\/conf\/captcha.html\"/" "$TEMP_CONFIG"
        
        if ! mv "$TEMP_CONFIG" "$DYNAMIC_CONFIG_PATH"; then
            print_error "Failed to update crowdsec middleware configuration"
            cp "$BACKUP_CONFIG" "$DYNAMIC_CONFIG_PATH"
            return 1
        fi
        
        print_success "Updated existing crowdsec middleware with captcha configuration"
    else
        print_error "crowdsec middleware not found in dynamic_config.yml"
        print_warning "Make sure you have the crowdsec middleware configured first"
        return 1
    fi
    
    echo -e "${YELLOW}Restarting Traefik to apply changes...${NC}"
    if ! docker restart traefik; then
        print_error "Failed to restart Traefik container"
        return 1
    fi
    
    sleep 5
    
    echo -e "${YELLOW}Restarting CrowdSec to apply profile changes...${NC}"
    if ! docker restart crowdsec; then
        print_error "Failed to restart CrowdSec container"
        return 1
    fi
    
    sleep 5
    
    echo -e "\n${GREEN}Captcha protection setup completed.${NC}"
    echo -e "${YELLOW}Note: To test the captcha, you can add a test captcha decision:${NC}"
    echo -e "${CYAN}docker exec crowdsec cscli decisions add --ip <test-ip> --type captcha -d 1h${NC}"
    
    return 0
}
