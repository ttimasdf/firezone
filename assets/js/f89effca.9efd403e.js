"use strict";(self.webpackChunkfirezone_docs=self.webpackChunkfirezone_docs||[]).push([[3409],{3905:(e,n,t)=>{t.d(n,{Zo:()=>d,kt:()=>f});var o=t(7294);function i(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function r(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);n&&(o=o.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,o)}return t}function a(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?r(Object(t),!0).forEach((function(n){i(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):r(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function l(e,n){if(null==e)return{};var t,o,i=function(e,n){if(null==e)return{};var t,o,i={},r=Object.keys(e);for(o=0;o<r.length;o++)t=r[o],n.indexOf(t)>=0||(i[t]=e[t]);return i}(e,n);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(o=0;o<r.length;o++)t=r[o],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var s=o.createContext({}),p=function(e){var n=o.useContext(s),t=n;return e&&(t="function"==typeof e?e(n):a(a({},n),e)),t},d=function(e){var n=p(e.components);return o.createElement(s.Provider,{value:n},e.children)},u="mdxType",c={inlineCode:"code",wrapper:function(e){var n=e.children;return o.createElement(o.Fragment,{},n)}},g=o.forwardRef((function(e,n){var t=e.components,i=e.mdxType,r=e.originalType,s=e.parentName,d=l(e,["components","mdxType","originalType","parentName"]),u=p(t),g=i,f=u["".concat(s,".").concat(g)]||u[g]||c[g]||r;return t?o.createElement(f,a(a({ref:n},d),{},{components:t})):o.createElement(f,a({ref:n},d))}));function f(e,n){var t=arguments,i=n&&n.mdxType;if("string"==typeof e||i){var r=t.length,a=new Array(r);a[0]=g;var l={};for(var s in n)hasOwnProperty.call(n,s)&&(l[s]=n[s]);l.originalType=e,l[u]="string"==typeof e?e:i,a[1]=l;for(var p=2;p<r;p++)a[p]=t[p];return o.createElement.apply(null,a)}return o.createElement.apply(null,t)}g.displayName="MDXCreateElement"},9388:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>s,contentTitle:()=>a,default:()=>m,frontMatter:()=>r,metadata:()=>l,toc:()=>p});var o=t(7462),i=(t(7294),t(3905));const r={title:"Upgrade",sidebar_position:3},a=void 0,l={unversionedId:"administer/upgrade",id:"administer/upgrade",title:"Upgrade",description:"Upgrading Firezone will pause all VPN sessions and temporarily bring",source:"@site/docs/administer/upgrade.mdx",sourceDirName:"administer",slug:"/administer/upgrade",permalink:"/administer/upgrade",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/www/docs/administer/upgrade.mdx",tags:[],version:"current",sidebarPosition:3,frontMatter:{title:"Upgrade",sidebar_position:3},sidebar:"tutorialSidebar",previous:{title:"Migrate to Docker",permalink:"/administer/migrate"},next:{title:"Backup and Restore",permalink:"/administer/backup"}},s={},p=[{value:"Upgrading to 0.7.x",id:"upgrading-to-07x",level:2},{value:"Upgrading to &gt;= 0.6.12",id:"upgrading-to--0612",level:2},{value:"WIREGUARD_* env vars",id:"wireguard_-env-vars",level:3},{value:"<code>AUTH_OIDC_JSON</code> config",id:"auth_oidc_json-config",level:3},{value:"Fix IPv6",id:"fix-ipv6",level:3},{value:"Upgrading from 0.5.x to 0.6.x",id:"upgrading-from-05x-to-06x",level:2},{value:"Migrate to Docker",id:"migrate-to-docker",level:3},{value:"Update Configuration",id:"update-configuration",level:3},{value:"Upgrading from &lt; 0.5.0 to &gt;= 0.5.0",id:"upgrading-from--050-to--050",level:2},{value:"Bundled Nginx non_ssl_port (HTTP) requests removed",id:"bundled-nginx-non_ssl_port-http-requests-removed",level:3},{value:"ACME protocol support",id:"acme-protocol-support",level:3},{value:"Overlapping egress rule destinations",id:"overlapping-egress-rule-destinations",level:3},{value:"Preconfigured Okta and Google SSO",id:"preconfigured-okta-and-google-sso",level:3},{value:"Existing Google OAuth configuration",id:"existing-google-oauth-configuration",level:4},{value:"Existing Okta OAuth configuration",id:"existing-okta-oauth-configuration",level:4},{value:"Upgrading from 0.3.x to &gt;= 0.3.16",id:"upgrading-from-03x-to--0316",level:2},{value:"I have an existing OIDC integration",id:"i-have-an-existing-oidc-integration",level:3},{value:"I have an existing OAuth integration",id:"i-have-an-existing-oauth-integration",level:3},{value:"I have not integrated an identity provider",id:"i-have-not-integrated-an-identity-provider",level:3},{value:"Upgrading from 0.3.1 to &gt;= 0.3.2",id:"upgrading-from-031-to--032",level:2},{value:"Upgrading from 0.2.x to 0.3.x",id:"upgrading-from-02x-to-03x",level:2},{value:"Upgrading from 0.1.x to 0.2.x",id:"upgrading-from-01x-to-02x",level:2}],d=e=>function(n){return console.warn("Component "+e+" was not imported, exported, or provided by MDXProvider as global scope"),(0,i.kt)("div",n)},u=d("Tabs"),c=d("TabItem"),g={toc:p},f="wrapper";function m(e){let{components:n,...t}=e;return(0,i.kt)(f,(0,o.Z)({},g,t,{components:n,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Upgrading Firezone will pause all VPN sessions and temporarily bring\ndown the web UI."),(0,i.kt)("admonition",{type:"info"},(0,i.kt)("p",{parentName:"admonition"},"Automatic rollbacks are still under development. We recommend backing up\nrelevant ",(0,i.kt)("a",{parentName:"p",href:"/reference/file-and-directory-locations/"},"files and folders"),"\nbefore upgrading in case anything goes wrong.")),(0,i.kt)("p",null,"Follow the steps below to upgrade Firezone:"),(0,i.kt)(u,{mdxType:"Tabs"},(0,i.kt)(c,{label:"Docker",value:"docker",default:!0,mdxType:"TabItem"},(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"Change to your Firezone installation directory, by default ",(0,i.kt)("inlineCode",{parentName:"li"},"$HOME/.firezone"),":")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"cd $HOME/.firezone\n")),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"If your ",(0,i.kt)("inlineCode",{parentName:"li"},".env")," file has a ",(0,i.kt)("inlineCode",{parentName:"li"},"VERSION")," variable, update it to the desired version.\nBy default ",(0,i.kt)("inlineCode",{parentName:"li"},"latest")," is assumed if not set. This variable is read in newer versions\nof the docker-compose.yml template to populate the ",(0,i.kt)("inlineCode",{parentName:"li"},"image:")," key for the ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone"),"\nservice."),(0,i.kt)("li",{parentName:"ol"},"Update service images:")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"docker compose pull\n")),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"Re-up the services (",(0,i.kt)("strong",{parentName:"li"},"warning: this will restart updated services"),"):")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"docker compose up -d\n"))),(0,i.kt)(c,{label:"Omnibus",value:"omnibus",mdxType:"TabItem"},(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"If not setup already, install our package repository based on your distro's\npackage format:")),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://cloudsmith.io/~firezone/repos/firezone/setup/#formats-deb"},"deb packages")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://cloudsmith.io/~firezone/repos/firezone/setup/#formats-rpm"},"rpm packages"))),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},"Upgrade the ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone")," package using your distro's package manager."),(0,i.kt)("li",{parentName:"ol"},"Run ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone-ctl reconfigure")," to pick up the new changes."),(0,i.kt)("li",{parentName:"ol"},"Run ",(0,i.kt)("inlineCode",{parentName:"li"},"firezone-ctl restart")," to restart services.")))),(0,i.kt)("p",null,"If you hit any issues, please let us know by ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/firezone/firezone/issues/new/choose"},"filing an\nissue"),"."),(0,i.kt)("h2",{id:"upgrading-to-07x"},"Upgrading to 0.7.x"),(0,i.kt)("p",null,"Firezone 0.7.0 introduces a new ",(0,i.kt)("a",{parentName:"p",href:"/reference/rest-api/"},"REST API")," that allows administrators\nto automate much of the day to day configuration of Firezone."),(0,i.kt)("p",null,"The REST API ",(0,i.kt)("inlineCode",{parentName:"p"},"/v0/configuration")," endpoint supersedes some of the previous environment\nvariables used for WireGuard server configuration."),(0,i.kt)("p",null,"If you're running Firezone ","<"," 0.6, we recommend updating to the latest\n0.6.x release ",(0,i.kt)("strong",{parentName:"p"},"before")," upgrading to 0.7. This will ensure any environment variables\nare properly parsed and migrated into the DB as runtime ",(0,i.kt)("inlineCode",{parentName:"p"},"configurations"),"."),(0,i.kt)("p",null,(0,i.kt)("strong",{parentName:"p"},"Note"),": Omnibus deployments are deprecated in 0.7.x and will be removed in Firezone\n0.8 and above. We recommend ",(0,i.kt)("a",{parentName:"p",href:"/administer/migrate/"},"migrating your installation")," to\nDocker if you haven't done so already."),(0,i.kt)("h2",{id:"upgrading-to--0612"},"Upgrading to >= 0.6.12"),(0,i.kt)("h3",{id:"wireguard_-env-vars"},"WIREGUARD_* env vars"),(0,i.kt)("p",null,"Firezone 0.6.12 moves the ",(0,i.kt)("inlineCode",{parentName:"p"},"WIREGUARD_ALLOWED_IPS"),", ",(0,i.kt)("inlineCode",{parentName:"p"},"WIREGUARD_PERSISTENT_KEEPALIVE"),",\nand ",(0,i.kt)("inlineCode",{parentName:"p"},"WIREGUARD_DNS")," environment variables to the database to be configured in the\nUI at ",(0,i.kt)("inlineCode",{parentName:"p"},"/settings/client_defaults"),". If the corresponding value at\n",(0,i.kt)("inlineCode",{parentName:"p"},"/settings/client_defaults")," was empty, the environment variable's value was used to\npopulate the field."),(0,i.kt)("p",null,"This is a small step in our quest to move more runtime configuration from environment\nvariables to the DB."),(0,i.kt)("h3",{id:"auth_oidc_json-config"},(0,i.kt)("inlineCode",{parentName:"h3"},"AUTH_OIDC_JSON")," config"),(0,i.kt)("p",null,"Similar to the ",(0,i.kt)("inlineCode",{parentName:"p"},"WIREGUARD_*")," env vars above, the ",(0,i.kt)("inlineCode",{parentName:"p"},"AUTH_OIDC_JSON")," env var has similarly\nbeen moved to the database and can be configured at ",(0,i.kt)("inlineCode",{parentName:"p"},"/settings/site"),". In Firezone 0.7 this\nis now configurable via the ",(0,i.kt)("a",{parentName:"p",href:"/reference/rest-api/configurations"},"REST API")," as well."),(0,i.kt)("h3",{id:"fix-ipv6"},"Fix IPv6"),(0,i.kt)("p",null,"0.6.12 fixes IPv6 routing within Docker networks.\nTo enable, add IPv6 addresses to your ",(0,i.kt)("inlineCode",{parentName:"p"},"$HOME/.firezone/docker-compose.yml")," by setting the following fields:"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-yaml"},"services:\n  firezone:\n    networks:\n      firezone-network:\n        ipv6_address: 2001:3990:3990::99\n\n# ...\nnetworks:\n  firezone-network:\n    ipam:\n      config:\n        - subnet: 2001:3990:3990::/64\n        - gateway: 2001:3990:3990::1\n")),(0,i.kt)("p",null,"You also need to update the Docker daemon to enable IPv6. See our ",(0,i.kt)("a",{parentName:"p",href:"https://docs.firezone.dev/deploy/docker/#step-4-enable-ipv6-optional"},"IPv6 guide")," for more info."),(0,i.kt)("h2",{id:"upgrading-from-05x-to-06x"},"Upgrading from 0.5.x to 0.6.x"),(0,i.kt)("p",null,"Firezone 0.6 introduces ",(0,i.kt)("strong",{parentName:"p"},"Docker support"),", SAML 2.0 authentication,\nmore granular user provisioning options, and a slew of minor improvements and bugfixes."),(0,i.kt)("h3",{id:"migrate-to-docker"},"Migrate to Docker"),(0,i.kt)("p",null,"Docker is now the preferred way to deploy and manage Firezone. See the ",(0,i.kt)("a",{parentName:"p",href:"/administer/migrate/"},"migration\nguide")," to migrate today. In most cases this can be done in a few minutes\nusing our automatic migration script."),(0,i.kt)("h3",{id:"update-configuration"},"Update Configuration"),(0,i.kt)("p",null,"Some configuration variables have recently moved to the DB in order to be configurable\nat runtime. Check the ",(0,i.kt)("a",{parentName:"p",href:"/deploy/configure/"},"configure guide")," for more information."),(0,i.kt)("h2",{id:"upgrading-from--050-to--050"},"Upgrading from < 0.5.0 to >= 0.5.0"),(0,i.kt)("p",null,"0.5.0 introduces a few breaking changes and configuration updates that will need\nto be addressed. Read more below."),(0,i.kt)("h3",{id:"bundled-nginx-non_ssl_port-http-requests-removed"},"Bundled Nginx non_ssl_port (HTTP) requests removed"),(0,i.kt)("p",null,"0.5.0 and above removes the ",(0,i.kt)("inlineCode",{parentName:"p"},"force_ssl")," and ",(0,i.kt)("inlineCode",{parentName:"p"},"non_ssl_port")," settings for\nNginx. SSL is required for Firezone to function; if you're using (or would like\nto use) your own reverse proxy, we recommend disabling the bundle Nginx service\nby setting ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['nginx']['enabled'] = false")," and pointing your\nreverse proxy directly to the Phoenix app on port 13000 (by default)."),(0,i.kt)("p",null,"Read more about setting up a custom reverse proxy\n",(0,i.kt)("a",{parentName:"p",href:"/deploy/advanced/reverse-proxy/"},"here"),"."),(0,i.kt)("h3",{id:"acme-protocol-support"},"ACME protocol support"),(0,i.kt)("p",null,"0.5.0 introduces ACME protocol support for automatically renewing SSL\ncertificates with the bundled Nginx service. To enable,"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Make sure ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['external_url']")," contains a valid FQDN that\nresolves to your server's public IP address.")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Ensure port ",(0,i.kt)("inlineCode",{parentName:"p"},"80/tcp")," is reachable")),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("p",{parentName:"li"},"Enable ACME protocol support with\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['ssl']['acme']['enabled'] = true")," in your config file."))),(0,i.kt)("h3",{id:"overlapping-egress-rule-destinations"},"Overlapping egress rule destinations"),(0,i.kt)("p",null,"Firezone 0.5.0 removes the ability to add rules with overlapping destinations.\nWhen upgrading to 0.5.0, our migration script will automatically detect these\ncases and ",(0,i.kt)("strong",{parentName:"p"},"keep only the rules whose destination encompasses the other rule"),".\nIf this is OK, ",(0,i.kt)("strong",{parentName:"p"},"there is nothing you need to do"),"."),(0,i.kt)("p",null,"Otherwise, we recommend modifying your ruleset to eliminate these cases before\nupgrading."),(0,i.kt)("h3",{id:"preconfigured-okta-and-google-sso"},"Preconfigured Okta and Google SSO"),(0,i.kt)("p",null,"Firezone 0.5.0 removes support for the old-style Okta and Google SSO\nconfiguration in favor of the new, more flexible OIDC-based configuration.\nIf you have any configuration under the\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['authentication']['okta']")," or\n",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['authentication']['google']")," keys, ",(0,i.kt)("strong",{parentName:"p"},"you need to migrate\nthese to our OIDC-based configuration using the guide below.")),(0,i.kt)("h4",{id:"existing-google-oauth-configuration"},"Existing Google OAuth configuration"),(0,i.kt)("p",null,"Remove these lines containing the old Google OAuth configs from your configuration\nfile located at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rb"},"default['firezone']['authentication']['google']['enabled']\ndefault['firezone']['authentication']['google']['client_id']\ndefault['firezone']['authentication']['google']['client_secret']\ndefault['firezone']['authentication']['google']['redirect_uri']\n")),(0,i.kt)("p",null,"Then, follow the instructions ",(0,i.kt)("a",{parentName:"p",href:"/authenticate/oidc/google/"},"here")," to configure Google\nas an OIDC provider."),(0,i.kt)("h4",{id:"existing-okta-oauth-configuration"},"Existing Okta OAuth configuration"),(0,i.kt)("p",null,"Remove these lines containing the old Okta OAuth configs from your configuration\nfile located at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rb"},"default['firezone']['authentication']['okta']['enabled']\ndefault['firezone']['authentication']['okta']['client_id']\ndefault['firezone']['authentication']['okta']['client_secret']\ndefault['firezone']['authentication']['okta']['site']\n")),(0,i.kt)("p",null,"Then, follow the instructions ",(0,i.kt)("a",{parentName:"p",href:"/authenticate/oidc/okta/"},"here")," to configure Okta as\nan OIDC provider."),(0,i.kt)("h2",{id:"upgrading-from-03x-to--0316"},"Upgrading from 0.3.x to >= 0.3.16"),(0,i.kt)("p",null,"Follow the instructions below based on your current version and setup:"),(0,i.kt)("h3",{id:"i-have-an-existing-oidc-integration"},"I have an existing OIDC integration"),(0,i.kt)("p",null,"Upgrading to >= 0.3.16 requires the ",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," scope for some OIDC providers\nto obtain a refresh token.\nThis ensures Firezone syncs with the identity provider and VPN access is terminated\nonce the user is removed. Previous versions of Firezone do not have this capability.\nUsers who are removed from your identity provider will still have active VPN sessions\nin some cases."),(0,i.kt)("p",null,"For OIDC providers that support the ",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," scope, you will need to add\n",(0,i.kt)("inlineCode",{parentName:"p"},"offline_access")," to the ",(0,i.kt)("inlineCode",{parentName:"p"},"scope")," parameter of your OIDC config. The\nFirezone configuration file can be found at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")," and requires\nrunning ",(0,i.kt)("inlineCode",{parentName:"p"},"firezone-ctl reconfigure")," to pick up the changes."),(0,i.kt)("p",null,"If Firezone is able to successfully retrieve the refresh token, you will see\nthe ",(0,i.kt)("strong",{parentName:"p"},"OIDC Connections")," heading in the user details page of the web UI for\nusers authenticated through your OIDC provider."),(0,i.kt)("p",null,(0,i.kt)("img",{parentName:"p",src:"https://user-images.githubusercontent.com/52545545/173169922-b0e5f2f1-74d5-4313-b839-6a001041c07e.png",alt:"OIDC Connections"})),(0,i.kt)("p",null,"If this does not work, you will need to delete your existing OAuth app\nand repeat the OIDC setup steps to\n",(0,i.kt)("a",{parentName:"p",href:"/authenticate/oidc/"},"create a new app integration")," ."),(0,i.kt)("h3",{id:"i-have-an-existing-oauth-integration"},"I have an existing OAuth integration"),(0,i.kt)("p",null,"Prior to 0.3.11, Firezone used pre-configured OAuth2 providers. Follow the\ninstructions ",(0,i.kt)("a",{parentName:"p",href:"/authenticate/oidc/"},"here")," to migrate to OIDC."),(0,i.kt)("h3",{id:"i-have-not-integrated-an-identity-provider"},"I have not integrated an identity provider"),(0,i.kt)("p",null,"No action needed. You can follow the instructions\n",(0,i.kt)("a",{parentName:"p",href:"/authenticate/oidc"},"here"),"\nto enable SSO through an OIDC provider."),(0,i.kt)("h2",{id:"upgrading-from-031-to--032"},"Upgrading from 0.3.1 to >= 0.3.2"),(0,i.kt)("p",null,"The configuration option ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['fqdn']")," has been removed in favor\nof ",(0,i.kt)("inlineCode",{parentName:"p"},"default['firezone']['external_url']"),". Please set this to the\npublicly-accessible URL of your Firezone web portal. If left unspecified it will\ndefault to ",(0,i.kt)("inlineCode",{parentName:"p"},"https://")," + the FQDN of your server."),(0,i.kt)("p",null,"Reminder, the configuration file can be found at ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb"),".\nFor an exhaustive list of configuration variables and their descriptions, see the\n",(0,i.kt)("a",{parentName:"p",href:"/reference/configuration-file"},"configuration file reference"),"."),(0,i.kt)("h2",{id:"upgrading-from-02x-to-03x"},"Upgrading from 0.2.x to 0.3.x"),(0,i.kt)("p",null,"Starting with version 0.3.0, Firezone no longer stores device private\nkeys on the Firezone server. Any existing devices should continue to function\nas-is, but you will not be able to re-download or view these configurations in\nthe Firezone Web UI."),(0,i.kt)("h2",{id:"upgrading-from-01x-to-02x"},"Upgrading from 0.1.x to 0.2.x"),(0,i.kt)("p",null,"Firezone 0.2.x contains some configuration file changes that will need to be\nhandled manually if you're upgrading from 0.1.x. Run the commands below as root\nto perform the needed changes to your ",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb")," file."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"cp /etc/firezone/firezone.rb /etc/firezone/firezone.rb.bak\nsed -i \"s/\\['enable'\\]/\\['enabled'\\]/\" /etc/firezone/firezone.rb\necho \"default['firezone']['connectivity_checks']['enabled'] = true\" >> /etc/firezone/firezone.rb\necho \"default['firezone']['connectivity_checks']['interval'] = 3_600\" >> /etc/firezone/firezone.rb\nfirezone-ctl reconfigure\nfirezone-ctl restart\n")))}m.isMDXComponent=!0}}]);