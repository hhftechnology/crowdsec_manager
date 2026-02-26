package handlers

// DiscordTemplate is the template for discord.yaml
const DiscordTemplate = `
type: http
name: discord
log_level: info
format: |
  {
    "embeds": [
      {
        {{range . -}}
        {{$alert := . -}}
        {{range .Decisions -}}
        {{- $cti := .Value | CrowdsecCTI  -}}
        "timestamp": "{{$alert.StartAt}}",
        "title": "🚨 CrowdSec Security Alert",
        "color": 16711680,
        "description": "Potential threat detected. View details in [CrowdSec Console](<https://app.crowdsec.net/cti/{{.Value}}>)",
        "url": "https://app.crowdsec.net/cti/{{.Value}}",
        {{if $alert.Source.Cn -}}
        "image": {
          "url": "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}}&zoom=8.1848&marker=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:awesome;color:%23655e90;size:large;icon:industry|lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:material;color:%23ff3421;icontype:awesome&scaleFactor=2&apiKey={{env "GEOAPIFY_API_KEY"}}"
        },
        {{end}}
        "fields": [
              {
                "name": "Scenario",
                "value": "` + "`{{ .Scenario }}`" + `",
                "inline": false
              },
              {
                "name": "Source IP",
                "value": "[{{.Value}}](<https://www.whois.com/whois/{{.Value}}>)",
                "inline": false
              },
              {
                "name": "Ban Duration",
                "value": "{{.Duration}}",
                "inline": false
              },
              {{if $alert.Source.Cn -}}
              {
                "name": "Country",
                "value": "**{{$alert.Source.Cn}}** :flag_{{ $alert.Source.Cn | lower }}:",
                "inline": false
              }
              {{if $cti.Location.City -}}
              ,{
                "name": "City",
                "value": "**{{$cti.Location.City}}**",
                "inline": false
              },
              {
                "name": "Maliciousness",
                "value": "{{mulf $cti.GetMaliciousnessScore 100 | floor}} %",
                "inline": false
              }
              {{end}}
              {{end}}
              {{if not $alert.Source.Cn -}}
              ,{
                "name": "Location",
                "value": "Unknown :pirate_flag:",
                "inline": false
              }
              {{end}}
              {{end -}}
              {{end -}}
              {{range . -}}
              {{$alert := . -}}
              {{if GetMeta $alert "target_host" -}}
              ,{
                "name": "🎯 Target Host",
                "value": "` + "`{{GetMeta $alert \"target_host\"}}`" + `",
                "inline": false
              }
              {{end}}
              {{if GetMeta $alert "target_uri" -}}
              ,{
                "name": "🔗 Target URI",
                "value": "` + "`{{GetMeta $alert \"target_uri\"}}`" + `",
                "inline": false
              }
              {{end}}
              {{if GetMeta $alert "target_fqdn" -}}
              ,{
                "name": "🌐 Target URL",
                "value": "{{range (GetMeta $alert "target_fqdn" | uniq) -}}` + "`{{.}}`" + `\n{{ end -}}",
                "inline": false
              }
              {{end}}
              {{range .Meta -}}
                {{if and (ne .Key "target_host") (ne .Key "target_uri") (ne .Key "target_fqdn") -}}
                ,{
                  "name": "{{.Key}}",
                  "value": "{{ (splitList "," (.Value | replace "\"" "` + "`" + `" | replace "[" "" |replace "]" "")) | join "\\n"}}",
                  "inline": false
                }
                {{end -}}
              {{end -}}
              {{end -}}
        ]
      }
    ]
  }
url: https://discord.com/api/webhooks/${DISCORD_WEBHOOK_ID}/${DISCORD_WEBHOOK_TOKEN}
method: POST
headers:
  Content-Type: application/json
`
