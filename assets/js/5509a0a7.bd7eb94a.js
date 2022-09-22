"use strict";(self.webpackChunknew_docs=self.webpackChunknew_docs||[]).push([[4180],{3905:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>f});var r=n(7294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var l=r.createContext({}),s=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},p=function(e){var t=s(e.components);return r.createElement(l.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},u=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,o=e.originalType,l=e.parentName,p=c(e,["components","mdxType","originalType","parentName"]),u=s(n),f=i,m=u["".concat(l,".").concat(f)]||u[f]||d[f]||o;return n?r.createElement(m,a(a({ref:t},p),{},{components:n})):r.createElement(m,a({ref:t},p))}));function f(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=n.length,a=new Array(o);a[0]=u;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c.mdxType="string"==typeof e?e:i,a[1]=c;for(var s=2;s<o;s++)a[s]=n[s];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}u.displayName="MDXCreateElement"},2968:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>a,default:()=>d,frontMatter:()=>o,metadata:()=>c,toc:()=>s});var r=n(7462),i=(n(7294),n(3905));const o={title:"Generic OIDC Provider",sidebar_position:10},a=void 0,c={unversionedId:"authenticate/generic-oidc",id:"authenticate/generic-oidc",title:"Generic OIDC Provider",description:"The example below details the config settings required by Firezone to enable SSO",source:"@site/docs/authenticate/generic-oidc.md",sourceDirName:"authenticate",slug:"/authenticate/generic-oidc",permalink:"/authenticate/generic-oidc",draft:!1,editUrl:"https://github.com/firezone/firezone/tree/master/docs/authenticate/generic-oidc.md",tags:[],version:"current",sidebarPosition:10,frontMatter:{title:"Generic OIDC Provider",sidebar_position:10},sidebar:"tutorialSidebar",previous:{title:"Zitadel",permalink:"/authenticate/zitadel"},next:{title:"Administer",permalink:"/administer/"}},l={},s=[],p={toc:s};function d(e){let{components:t,...n}=e;return(0,i.kt)("wrapper",(0,r.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"The example below details the config settings required by Firezone to enable SSO\nthrough a generic OIDC provider. The configuration file can be found at\n",(0,i.kt)("inlineCode",{parentName:"p"},"/etc/firezone/firezone.rb"),". To pick up changes, run ",(0,i.kt)("inlineCode",{parentName:"p"},"firezone-ctl reconfigure"),"\nto update the application."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-ruby"},'# This is an example using Google and Okta as an SSO identity provider.\n# Multiple OIDC configs can be added to the same Firezone instance.\n\n# Firezone can disable a user\'s VPN if there\'s any error detected trying\n# to refresh their access_token. This is verified to work for Google, Okta, and\n# Azure SSO and is used to automatically disconnect a user\'s VPN if they\'re removed\n# from the OIDC provider. Leave this disabled if your OIDC provider\n# has issues refreshing access tokens as it could unexpectedly interrupt a\n# user\'s VPN session.\ndefault[\'firezone\'][\'authentication\'][\'disable_vpn_on_oidc_error\'] = false\n\ndefault[\'firezone\'][\'authentication\'][\'oidc\'] = {\n  google: {\n    discovery_document_uri: "https://accounts.google.com/.well-known/openid-configuration",\n    client_id: "<GOOGLE_CLIENT_ID>",\n    client_secret: "<GOOGLE_CLIENT_SECRET>",\n    redirect_uri: "https://firezone.example.com/auth/oidc/google/callback/",\n    response_type: "code",\n    scope: "openid email profile",\n    label: "Google"\n  },\n  okta: {\n    discovery_document_uri: "https://<OKTA_DOMAIN>/.well-known/openid-configuration",\n    client_id: "<OKTA_CLIENT_ID>",\n    client_secret: "<OKTA_CLIENT_SECRET>",\n    redirect_uri: "https://firezone.example.com/auth/oidc/okta/callback/",\n    response_type: "code",\n    scope: "openid email profile offline_access",\n    label: "Okta"\n  }\n}\n')),(0,i.kt)("p",null,"The following config settings are required for the integration:"),(0,i.kt)("ol",null,(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"discovery_document_uri"),": The\n",(0,i.kt)("a",{parentName:"li",href:"https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig"},"OpenID Connect provider configuration URI"),"\nwhich returns a JSON document used to construct subsequent requests to this\nOIDC provider."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"client_id"),": The client ID of the application."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"client_secret"),": The client secret of the application."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"redirect_uri"),": Instructs OIDC provider where to redirect after authentication.\nThis should be your Firezone ",(0,i.kt)("inlineCode",{parentName:"li"},"EXTERNAL_URL + /auth/oidc/<provider_key>/callback/"),"\n(e.g. ",(0,i.kt)("inlineCode",{parentName:"li"},"https://firezone.example.com/auth/oidc/google/callback/"),")."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"response_type"),": Set to ",(0,i.kt)("inlineCode",{parentName:"li"},"code"),"."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"scope"),": ",(0,i.kt)("a",{parentName:"li",href:"https://openid.net/specs/openid-connect-basic-1_0.html#Scopes"},"OIDC scopes"),"\nto obtain from your OIDC provider. This should be set to ",(0,i.kt)("inlineCode",{parentName:"li"},"openid email profile"),"\nor ",(0,i.kt)("inlineCode",{parentName:"li"},"openid email profile offline_access")," depending on the provider."),(0,i.kt)("li",{parentName:"ol"},(0,i.kt)("inlineCode",{parentName:"li"},"label"),": The button label text that shows up on your Firezone login screen.")))}d.isMDXComponent=!0}}]);